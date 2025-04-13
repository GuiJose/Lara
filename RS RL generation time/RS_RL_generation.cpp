#include <iostream>
#include <vector>
#include <sodium.h>
#include <omp.h>
#include <ctime>

using namespace std;

unsigned long long merkle_tree_hashes = 0;
unsigned long long leaf_nodes = 0;

vector<unsigned char> sha256(const vector<unsigned char> &input)
{
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, input.data(), input.size());

#pragma omp atomic
    merkle_tree_hashes++;

    return vector<unsigned char>(hash, hash + crypto_hash_sha256_BYTES);
}

class BloomFilter
{
public:
    BloomFilter(size_t size, size_t num_hashes) : size(size), num_hashes(num_hashes), filter((size + 7) / 8, 0) {}

    void insert(const string &item)
    {
        vector<unsigned char> item_bytes(item.begin(), item.end());
#pragma omp parallel for
        for (size_t i = 0; i < num_hashes; ++i)
        {
            vector<unsigned char> hash_input = item_bytes;
            hash_input.push_back(i);
            vector<unsigned char> hash_value = sha256(hash_input);
            size_t index = *reinterpret_cast<size_t *>(hash_value.data()) % size;
            size_t byte_index = index / 8;
            size_t bit_index = index % 8;

#pragma omp atomic
            filter[byte_index] |= (1 << bit_index);
        }
    }

    bool contains(const string &item)
    {
        vector<unsigned char> item_bytes(item.begin(), item.end());
        for (size_t i = 0; i < num_hashes; ++i)
        {
            vector<unsigned char> hash_input = item_bytes;
            hash_input.push_back(i);
            vector<unsigned char> hash_value = sha256(hash_input);
            size_t index = *reinterpret_cast<size_t *>(hash_value.data()) % size;
            size_t byte_index = index / 8;
            size_t bit_index = index % 8;

            if (!(filter[byte_index] & (1 << bit_index)))
                return false;
        }
        return true;
    }

    const vector<unsigned char> &getFilter() const { return filter; }

private:
    size_t size;
    size_t num_hashes;
    vector<unsigned char> filter;
};

class MerkleTree
{
public:
    struct Node
    {
        std::vector<unsigned char> hash;
        Node *left;
        Node *right;

        Node(const std::vector<unsigned char> &val) : hash(val), left(nullptr), right(nullptr)
        {
#pragma omp atomic
            leaf_nodes++;
        }
    };

    MerkleTree(const std::vector<unsigned char> &data, size_t chunk_size)
    {
        size_t n = data.size();
        std::vector<Node *> leaves;
        leaves.reserve(n / chunk_size); // Reserve memory to reduce reallocations

        // Start total time for the entire Merkle Tree construction
        double start_total = omp_get_wtime();

        // Measure leaf node creation time
        double start_leaf = omp_get_wtime();

#pragma omp parallel
        {
            std::vector<Node *> local_leaves; // Local vector for each thread to store leaf nodes
#pragma omp for
            for (size_t i = 0; i < n; i += chunk_size)
            {
                std::vector<unsigned char> chunk(data.begin() + i, data.begin() + std::min(i + chunk_size, n));

                // Hash the chunk directly and create the leaf node in a single operation
                Node *node = new Node(sha256(chunk));

                // Store the node in the local vector to avoid contention
                local_leaves.push_back(node);
            }

#pragma omp critical
            {
                // Merge local leaves into global leaves after parallel work is done
                leaves.insert(leaves.end(), local_leaves.begin(), local_leaves.end());
            }
        }

        double end_leaf = omp_get_wtime();
        leaf_creation_time = end_leaf - start_leaf;

        // Measure Merkle tree hashing (building the tree)
        double start_tree_building = omp_get_wtime();

        // Optimized tree building loop, avoiding excessive memory allocation
        while (leaves.size() > 1)
        {
            std::vector<Node *> new_level;
            new_level.reserve(leaves.size() / 2); // Reserve memory to reduce reallocations

#pragma omp parallel
            {
                std::vector<Node *> local_new_level; // Local vector for each thread to store combined nodes
#pragma omp for
                for (size_t i = 0; i < leaves.size(); i += 2)
                {
                    // Combine two nodes' hashes directly
                    std::vector<unsigned char> combined_data = leaves[i]->hash;
                    if (i + 1 < leaves.size())
                        combined_data.insert(combined_data.end(), leaves[i + 1]->hash.begin(), leaves[i + 1]->hash.end());

                    Node *combined_node = new Node(sha256(combined_data));
                    combined_node->left = leaves[i];
                    combined_node->right = (i + 1 < leaves.size()) ? leaves[i + 1] : nullptr;

                    local_new_level.push_back(combined_node); // Add to local vector (no contention)
                }

#pragma omp critical
                {
                    new_level.insert(new_level.end(), local_new_level.begin(), local_new_level.end()); // Merge local vectors into new_level
                }
            }

            leaves = new_level; // Update leaves for the next level
        }

        root = leaves[0];

        double end_tree_building = omp_get_wtime();
        tree_building_time = end_tree_building - start_tree_building;

        // End total time
        double end_total = omp_get_wtime();
        total_merkle_time = end_total - start_total;
    }

    ~MerkleTree() { deleteTree(root); }

    std::vector<unsigned char> getRootHash() const { return root->hash; }

    double getLeafCreationTime() const { return leaf_creation_time; }
    double getTreeBuildingTime() const { return tree_building_time; }
    double getTotalMerkleTime() const { return total_merkle_time; }

private:
    void deleteTree(Node *node)
    {
        if (!node)
            return;
        deleteTree(node->left);
        deleteTree(node->right);
        delete node;
    }

    Node *root;
    double leaf_creation_time = 0.0;
    double tree_building_time = 0.0;
    double total_merkle_time = 0.0;
    static unsigned long long leaf_nodes;
};

// Initialize static variables
unsigned long long MerkleTree::leaf_nodes = 0;

// Ed25519 Signing function
string signEd25519(const vector<unsigned char> &data)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    unsigned char signed_message[crypto_sign_BYTES + crypto_hash_sha256_BYTES];
    unsigned long long signed_len;
    crypto_sign(signed_message, &signed_len, data.data(), data.size(), sk);
    return string(reinterpret_cast<char *>(signed_message), signed_len);
}

// Main function
int main()
{
    size_t filter_size = 800000; // bits
    size_t num_hashes = 3;
    size_t chunk_size = 1000; // chars

    double total_merkle_time = 0;
    double total_leaf_creation_time = 0;
    double total_tree_building_time = 0;
    unsigned long long total_leaf_nodes = 0;
    size_t num_runs = 100;

    for (size_t run = 0; run < num_runs; ++run)
    {
        // Creating Bloom Filter and inserting items
        BloomFilter bf(filter_size, num_hashes);
        bf.insert("item1");
        bf.insert("item2");
        bf.insert("item3");

        // Retrieving the Bloom filter bits
        const vector<unsigned char> &filter_bits = bf.getFilter();

        // Start Merkle Tree Construction
        clock_t start_time = clock();
        MerkleTree tree(filter_bits, chunk_size);
        vector<unsigned char> root_hash = tree.getRootHash();
        string signature = signEd25519(root_hash);
        clock_t end_time = clock();

        // Accumulate times and statistics
        total_merkle_time += tree.getTotalMerkleTime();
        total_leaf_creation_time += tree.getLeafCreationTime();
        total_tree_building_time += tree.getTreeBuildingTime();
        total_leaf_nodes += leaf_nodes;
    }

    // Calculate and print the average times
    cout << "Average Merkle Tree Total Construction Time: " << total_merkle_time / num_runs << " seconds" << endl;
    cout << "Average Leaf Node Creation Time: " << total_leaf_creation_time / num_runs << " seconds" << endl;
    cout << "Average Tree Hashing & Building Time: " << total_tree_building_time / num_runs << " seconds" << endl;
    cout << "Average Number of hashes calculated: " << merkle_tree_hashes / num_runs << endl;
    cout << "Average Number of leaf nodes in Merkle tree: " << total_leaf_nodes / num_runs << endl;

    return 0;
}
