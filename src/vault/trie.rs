//! Persistent hash trie for the registry snapshot.
//!
//! The registry is copy-on-write: readers load a snapshot without locking
//! and writers publish a new one. Before 1.2 every write copied the whole
//! `HashMap`, so `register`, `rotate` and `unregister` cost O(n) in the
//! number of keys. This trie shares every node a write does not touch: an
//! insert or remove copies only the nodes on the path to the changed
//! entry (at most 13 levels of 32-way branches, usually 2 to 4), so a
//! write costs O(log n) and does not depend on the size of the registry
//! in practice.
//!
//! Keys are addressed by a 64-bit hash supplied by the caller, five bits
//! per level, lowest bits first. Entries whose full hashes are equal share
//! a collision leaf and are told apart by key equality.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::Borrow;

/// Bits of the hash consumed per level.
const BITS: u32 = 5;
/// Mask for one level's fragment of the hash.
const MASK: u64 = (1 << BITS) - 1;

/// A persistent map from `K` to `V`, addressed by a caller-supplied hash.
///
/// Cloning is O(1) (one reference count). Every update returns a new map
/// and leaves `self` unchanged.
pub(crate) struct HashTrie<K, V> {
    root: Option<Arc<Node<K, V>>>,
    len: usize,
}

enum Node<K, V> {
    /// Interior node: one child per set bit of `bitmap`, in bit order.
    Branch {
        bitmap: u32,
        children: Vec<Arc<Node<K, V>>>,
    },
    /// One entry.
    Leaf { hash: u64, key: K, value: V },
    /// Two or more entries whose hashes are equal.
    Collision { hash: u64, entries: Vec<(K, V)> },
}

impl<K, V> Clone for HashTrie<K, V> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<K, V> Default for HashTrie<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// The 5-bit fragment of `hash` used at `shift`.
#[inline]
fn fragment(hash: u64, shift: u32) -> u32 {
    // `shift` is at most 60 (see `merge`), so the shift cannot overflow.
    #[allow(clippy::cast_possible_truncation)] // masked to 5 bits.
    let frag = ((hash >> shift) & MASK) as u32;
    frag
}

/// Index of the child for `bit` in a branch with `bitmap`.
#[inline]
fn child_index(bitmap: u32, bit: u32) -> usize {
    (bitmap & (bit - 1)).count_ones() as usize
}

impl<K, V> Node<K, V> {
    /// The full hash of a leaf or collision node.
    fn leaf_hash(&self) -> Option<u64> {
        match self {
            Self::Leaf { hash, .. } | Self::Collision { hash, .. } => Some(*hash),
            Self::Branch { .. } => None,
        }
    }
}

impl<K, V> HashTrie<K, V> {
    /// An empty map.
    pub(crate) const fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Number of entries.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// The value stored under `key` (whose hash is `hash`).
    pub(crate) fn get<Q>(&self, hash: u64, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let mut node = self.root.as_deref()?;
        let mut shift = 0;
        loop {
            match node {
                Node::Branch { bitmap, children } => {
                    let bit = 1u32 << fragment(hash, shift);
                    if bitmap & bit == 0 {
                        return None;
                    }
                    node = &children[child_index(*bitmap, bit)];
                    shift += BITS;
                }
                Node::Leaf {
                    hash: h,
                    key: k,
                    value,
                } => {
                    return (*h == hash && k.borrow() == key).then_some(value);
                }
                Node::Collision { hash: h, entries } => {
                    if *h != hash {
                        return None;
                    }
                    return entries
                        .iter()
                        .find(|(k, _)| k.borrow() == key)
                        .map(|(_, v)| v);
                }
            }
        }
    }

    /// Call `f` for every entry, in no particular order.
    pub(crate) fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        fn walk<K, V>(node: &Node<K, V>, f: &mut impl FnMut(&K, &V)) {
            match node {
                Node::Branch { children, .. } => {
                    for child in children {
                        walk(child, f);
                    }
                }
                Node::Leaf { key, value, .. } => f(key, value),
                Node::Collision { entries, .. } => {
                    for (k, v) in entries {
                        f(k, v);
                    }
                }
            }
        }
        if let Some(root) = &self.root {
            walk(root, &mut f);
        }
    }
}

impl<K: Clone + Eq, V: Clone> HashTrie<K, V> {
    /// A map with `key` set to `value`, and the value it replaced.
    pub(crate) fn insert(&self, hash: u64, key: K, value: V) -> (Self, Option<V>) {
        let (root, old) = match &self.root {
            None => (Arc::new(Node::Leaf { hash, key, value }), None),
            Some(root) => insert(root, 0, hash, key, value),
        };
        let len = if old.is_some() {
            self.len
        } else {
            self.len + 1
        };
        (
            Self {
                root: Some(root),
                len,
            },
            old,
        )
    }

    /// A map without `key`, and the value it held. `None` if `key` is not
    /// in the map (the map would be unchanged).
    pub(crate) fn remove<Q>(&self, hash: u64, key: &Q) -> Option<(Self, V)>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let root = self.root.as_ref()?;
        let (root, value) = remove(root, 0, hash, key)?;
        Some((
            Self {
                root,
                len: self.len - 1,
            },
            value,
        ))
    }
}

/// Insert into the subtree `node` found at `shift`.
fn insert<K: Clone + Eq, V: Clone>(
    node: &Arc<Node<K, V>>,
    shift: u32,
    hash: u64,
    key: K,
    value: V,
) -> (Arc<Node<K, V>>, Option<V>) {
    match &**node {
        Node::Branch { bitmap, children } => {
            let bit = 1u32 << fragment(hash, shift);
            let idx = child_index(*bitmap, bit);
            let mut children = children.clone();
            if bitmap & bit == 0 {
                children.insert(idx, Arc::new(Node::Leaf { hash, key, value }));
                (
                    Arc::new(Node::Branch {
                        bitmap: bitmap | bit,
                        children,
                    }),
                    None,
                )
            } else {
                let (child, old) = insert(&children[idx], shift + BITS, hash, key, value);
                children[idx] = child;
                (
                    Arc::new(Node::Branch {
                        bitmap: *bitmap,
                        children,
                    }),
                    old,
                )
            }
        }
        Node::Leaf {
            hash: h,
            key: k,
            value: v,
        } => {
            if *h != hash {
                let leaf = Arc::new(Node::Leaf { hash, key, value });
                return (merge(shift, Arc::clone(node), *h, leaf, hash), None);
            }
            if *k == key {
                return (Arc::new(Node::Leaf { hash, key, value }), Some(v.clone()));
            }
            (
                Arc::new(Node::Collision {
                    hash,
                    entries: alloc::vec![(k.clone(), v.clone()), (key, value)],
                }),
                None,
            )
        }
        Node::Collision { hash: h, entries } => {
            if *h != hash {
                let leaf = Arc::new(Node::Leaf { hash, key, value });
                return (merge(shift, Arc::clone(node), *h, leaf, hash), None);
            }
            let mut entries = entries.clone();
            let old = if let Some(slot) = entries.iter_mut().find(|(k, _)| *k == key) {
                Some(core::mem::replace(&mut slot.1, value))
            } else {
                entries.push((key, value));
                None
            };
            (Arc::new(Node::Collision { hash, entries }), old)
        }
    }
}

/// A subtree at `shift` holding the two leaves `a` (hash `ha`) and `b`
/// (hash `hb`), which must differ.
fn merge<K, V>(
    shift: u32,
    a: Arc<Node<K, V>>,
    ha: u64,
    b: Arc<Node<K, V>>,
    hb: u64,
) -> Arc<Node<K, V>> {
    debug_assert_ne!(ha, hb);
    // Two different 64-bit hashes differ in some fragment at or below
    // shift 60, so the recursion stops before the shift overflows.
    let fa = fragment(ha, shift);
    let fb = fragment(hb, shift);
    if fa == fb {
        let child = merge(shift + BITS, a, ha, b, hb);
        Arc::new(Node::Branch {
            bitmap: 1 << fa,
            children: alloc::vec![child],
        })
    } else {
        let children = if fa < fb {
            alloc::vec![a, b]
        } else {
            alloc::vec![b, a]
        };
        Arc::new(Node::Branch {
            bitmap: (1 << fa) | (1 << fb),
            children,
        })
    }
}

/// Remove from the subtree `node` at `shift`. `None` if the key is not
/// there; otherwise the replacement subtree (`None` if it became empty)
/// and the removed value.
#[allow(clippy::type_complexity)]
fn remove<K, V, Q>(
    node: &Arc<Node<K, V>>,
    shift: u32,
    hash: u64,
    key: &Q,
) -> Option<(Option<Arc<Node<K, V>>>, V)>
where
    K: Clone + Eq + Borrow<Q>,
    V: Clone,
    Q: Eq + ?Sized,
{
    match &**node {
        Node::Leaf {
            hash: h,
            key: k,
            value,
        } => (*h == hash && k.borrow() == key).then(|| (None, value.clone())),
        Node::Collision { hash: h, entries } => {
            if *h != hash {
                return None;
            }
            let pos = entries.iter().position(|(k, _)| k.borrow() == key)?;
            let mut entries = entries.clone();
            let (_, value) = entries.remove(pos);
            let replacement = if entries.len() == 1 {
                let (key, value) = entries.pop()?;
                Node::Leaf { hash, key, value }
            } else {
                Node::Collision { hash, entries }
            };
            Some((Some(Arc::new(replacement)), value))
        }
        Node::Branch { bitmap, children } => {
            let bit = 1u32 << fragment(hash, shift);
            if bitmap & bit == 0 {
                return None;
            }
            let idx = child_index(*bitmap, bit);
            let (child, value) = remove(&children[idx], shift + BITS, hash, key)?;
            let mut children = children.clone();
            let bitmap = if let Some(child) = child {
                children[idx] = child;
                *bitmap
            } else {
                let _ = children.remove(idx);
                bitmap & !bit
            };
            // A branch left with a single leaf is replaced by that leaf:
            // lookups compare the full hash at a leaf, so a leaf can sit at
            // any depth on its hash's path. This keeps the trie as shallow
            // as its contents need.
            let replacement = match children.len() {
                0 => None,
                1 if children[0].leaf_hash().is_some() => children.pop(),
                _ => Some(Arc::new(Node::Branch { bitmap, children })),
            };
            Some((replacement, value))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};

    /// A hash with few distinct values, to force collisions and deep
    /// shared prefixes.
    fn weak_hash(k: u32) -> u64 {
        u64::from(k % 7) | (u64::from(k % 3) << 60)
    }

    #[test]
    fn empty_map() {
        let t: HashTrie<u32, u32> = HashTrie::new();
        assert_eq!(t.len(), 0);
        assert!(t.get(1, &1).is_none());
        assert!(t.remove(1, &1).is_none());
    }

    #[test]
    fn insert_get_replace_remove() {
        let t = HashTrie::new();
        let (t, old) = t.insert(5, 5u32, "five".to_string());
        assert!(old.is_none());
        let (t2, old) = t.insert(5, 5, "FIVE".to_string());
        assert_eq!(old.as_deref(), Some("five"));
        // The old version is unchanged.
        assert_eq!(t.get(5, &5).map(String::as_str), Some("five"));
        assert_eq!(t2.get(5, &5).map(String::as_str), Some("FIVE"));
        assert_eq!(t2.len(), 1);
        let (t3, v) = t2.remove(5, &5).unwrap();
        assert_eq!(v, "FIVE");
        assert_eq!(t3.len(), 0);
        assert!(t3.get(5, &5).is_none());
        assert_eq!(t2.len(), 1);
    }

    #[test]
    fn full_hash_collisions_are_kept_apart() {
        let mut t = HashTrie::new();
        for k in 0..10u32 {
            t = t.insert(42, k, k * 10).0;
        }
        assert_eq!(t.len(), 10);
        for k in 0..10 {
            assert_eq!(t.get(42, &k), Some(&(k * 10)));
        }
        assert!(t.get(42, &99).is_none());
        for k in 0..10 {
            t = t.remove(42, &k).unwrap().0;
            assert!(t.get(42, &k).is_none());
            for rest in k + 1..10 {
                assert_eq!(t.get(42, &rest), Some(&(rest * 10)));
            }
        }
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn hashes_differing_only_in_the_top_bits() {
        let a = 1u64 << 63;
        let b = 1u64 << 62;
        let t = HashTrie::new().insert(a, 1u8, 'a').0.insert(b, 2, 'b').0;
        assert_eq!(t.get(a, &1), Some(&'a'));
        assert_eq!(t.get(b, &2), Some(&'b'));
        assert!(t.get(0, &1).is_none());
        let t = t.remove(a, &1).unwrap().0;
        assert_eq!(t.get(b, &2), Some(&'b'));
    }

    /// Agrees with a `BTreeMap` over a mixed sequence of operations, with
    /// sequential hashes (like key ids) and with a hash that collides.
    #[test]
    fn matches_a_btreemap() {
        for weak in [false, true] {
            let hash = |k: u32| if weak { weak_hash(k) } else { u64::from(k) };
            let mut model = BTreeMap::new();
            let mut t = HashTrie::new();
            let mut versions = Vec::new();
            let mut x = 12345u32;
            for step in 0..3000u32 {
                // Small LCG: deterministic and good enough to mix inserts
                // and removes over a few hundred keys.
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                let k = (x >> 8) % 400;
                if x % 3 == 0 {
                    let expect = model.remove(&k);
                    match t.remove(hash(k), &k) {
                        Some((next, v)) => {
                            assert_eq!(Some(v), expect);
                            t = next;
                        }
                        None => assert!(expect.is_none()),
                    }
                } else {
                    let expect = model.insert(k, step);
                    let (next, old) = t.insert(hash(k), k, step);
                    assert_eq!(old, expect);
                    t = next;
                }
                assert_eq!(t.len(), model.len());
                if step % 500 == 0 {
                    versions.push((t.clone(), model.clone()));
                }
            }
            for k in 0..400 {
                assert_eq!(t.get(hash(k), &k), model.get(&k));
            }
            let mut seen = BTreeMap::new();
            t.for_each(|k, v| {
                assert!(seen.insert(*k, *v).is_none());
            });
            assert_eq!(seen, model);
            // Older versions still read as they did.
            for (old, old_model) in &versions {
                for k in 0..400 {
                    assert_eq!(old.get(hash(k), &k), old_model.get(&k));
                }
            }
        }
    }

    /// Removing everything collapses the trie back to empty, so lookups of
    /// removed keys never find stale branches.
    #[test]
    fn removing_everything_empties_the_trie() {
        let mut t = HashTrie::new();
        for k in 0..2000u64 {
            t = t.insert(k.wrapping_mul(0x9e37_79b9_7f4a_7c15), k, k).0;
        }
        for k in 0..2000u64 {
            t = t
                .remove(k.wrapping_mul(0x9e37_79b9_7f4a_7c15), &k)
                .unwrap()
                .0;
        }
        assert_eq!(t.len(), 0);
        assert!(t.root.is_none());
    }
}
