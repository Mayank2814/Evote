#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
using namespace std;

using json = nlohmann::json;

// Vote structure
struct Vote {
    string voterId;
    string voterName;
    string voterEmail;
    string constituency;
    string candidate;
    string timestamp;
    string voteHash;
    string previousHash;
    
    Vote() = default;
    
    Vote(const std::string& id, const std::string& name, const std::string& email,
         const std::string& consti, const std::string& cand, const std::string& time)
        : voterId(id), voterName(name), voterEmail(email), constituency(consti),
          candidate(cand), timestamp(time) {}
};

// Merkle Tree Node
struct MerkleNode {
    std::string hash;
    MerkleNode* left;
    MerkleNode* right;
    
    MerkleNode(const std::string& h) : hash(h), left(nullptr), right(nullptr) {}
};

// Hash Chain Block
struct HashBlock {
    string blockHash;
    string previousHash;
    string voteHash;
    string timestamp;
    int nonce;
    
    HashBlock() : nonce(0) {}
};

class EVotingSystem {
private:
    std::vector<Vote> votes;
    std::vector<HashBlock> hashChain;
    MerkleNode* merkleRoot;
    std::map<std::string, Vote> voterMap; // For quick lookup
    
    // Generate SHA-256 hash
    std::string generateSHA256(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, input.c_str(), input.length());
        SHA256_Final(hash, &sha256);
        
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }
    
    // Generate vote hash
    std::string generateVoteHash(const Vote& vote) {
        std::string data = vote.voterId + vote.voterName + vote.voterEmail + 
                          vote.constituency + vote.candidate + vote.timestamp;
        return generateSHA256(data);
    }
    
    // Build Merkle Tree
    MerkleNode* buildMerkleTree(const std::vector<std::string>& hashes) {
        if (hashes.empty()) return nullptr;
        if (hashes.size() == 1) return new MerkleNode(hashes[0]);
        
        std::vector<MerkleNode*> nodes;
        for (const auto& hash : hashes) {
            nodes.push_back(new MerkleNode(hash));
        }
        
        while (nodes.size() > 1) {
            std::vector<MerkleNode*> newLevel;
            
            for (size_t i = 0; i < nodes.size(); i += 2) {
                std::string combinedHash;
                if (i + 1 < nodes.size()) {
                    combinedHash = generateSHA256(nodes[i]->hash + nodes[i + 1]->hash);
                } else {
                    combinedHash = generateSHA256(nodes[i]->hash + nodes[i]->hash);
                }
                
                MerkleNode* parent = new MerkleNode(combinedHash);
                parent->left = nodes[i];
                if (i + 1 < nodes.size()) {
                    parent->right = nodes[i + 1];
                }
                newLevel.push_back(parent);
            }
            
            nodes = newLevel;
        }
        
        return nodes[0];
    }
    
    // Add block to hash chain
    void addToHashChain(const std::string& voteHash) {
        HashBlock block;
        block.voteHash = voteHash;
        block.timestamp = getCurrentTimestamp();
        
        if (hashChain.empty()) {
            block.previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
        } else {
            block.previousHash = hashChain.back().blockHash;
        }
        
        // Simple proof of work (find nonce)
        std::string target = "0000"; // 4 leading zeros
        do {
            block.nonce++;
            std::string data = block.previousHash + block.voteHash + block.timestamp + std::to_string(block.nonce);
            block.blockHash = generateSHA256(data);
        } while (block.blockHash.substr(0, 4) != target);
        
        hashChain.push_back(block);
    }
    
    // Get current timestamp
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    // Clean up Merkle tree
    void cleanupMerkleTree(MerkleNode* node) {
        if (node) {
            cleanupMerkleTree(node->left);
            cleanupMerkleTree(node->right);
            delete node;
        }
    }
    
public:
    EVotingSystem() : merkleRoot(nullptr) {}
    
    ~EVotingSystem() {
        cleanupMerkleTree(merkleRoot);
    }
    
    // Submit a vote
    bool submitVote(const std::string& voterId, const std::string& voterName,
                   const std::string& voterEmail, const std::string& constituency,
                   const std::string& candidate) {
        
        // Check if voter already voted
        if (voterMap.find(voterId) != voterMap.end()) {
            std::cout << "Error: Voter " << voterId << " has already voted!" << std::endl;
            return false;
        }
        
        // Create vote
        Vote vote(voterId, voterName, voterEmail, constituency, candidate, getCurrentTimestamp());
        
        // Generate vote hash
        vote.voteHash = generateVoteHash(vote);
        
        // Add to hash chain
        if (!hashChain.empty()) {
            vote.previousHash = hashChain.back().blockHash;
        } else {
            vote.previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
        }
        
        // Store vote
        votes.push_back(vote);
        voterMap[voterId] = vote;
        
        // Add to hash chain
        addToHashChain(vote.voteHash);
        
        // Rebuild Merkle tree
        rebuildMerkleTree();
        
        cout << "Vote submitted successfully for voter: " << voterId << std::endl;
        cout << "Vote Hash: " << vote.voteHash << std::endl;
        cout << "Block Hash: " << hashChain.back().blockHash << std::endl;
        
        return true;
    }
    
    // Verify a vote
    json verifyVote(const std::string& voterId) {
        json result;
        
        auto it = voterMap.find(voterId);
        if (it == voterMap.end()) {
            result["success"] = false;
            result["message"] = "Vote not found for this Voter ID";
            return result;
        }
        
        const Vote& vote = it->second;
        
        // Verify vote hash
        std::string calculatedHash = generateVoteHash(vote);
        bool hashValid = (calculatedHash == vote.voteHash);
        
        // Verify in hash chain
        bool inChain = false;
        for (const auto& block : hashChain) {
            if (block.voteHash == vote.voteHash) {
                inChain = true;
                break;
            }
        }
        
        result["success"] = true;
        result["voterId"] = vote.voterId;
        result["voterName"] = vote.voterName;
        result["constituency"] = vote.constituency;
        result["candidate"] = vote.candidate;
        result["timestamp"] = vote.timestamp;
        result["voteHash"] = vote.voteHash;
        result["hashValid"] = hashValid;
        result["inChain"] = inChain;
        result["message"] = "Vote verified successfully";
        
        return result;
    }
    
    // Get election results
    json getElectionResults() {
        json results;
        std::map<std::string, int> candidateVotes;
        
        for (const auto& vote : votes) {
            candidateVotes[vote.candidate]++;
        }
        
        results["totalVotes"] = votes.size();
        results["candidates"] = candidateVotes;
        
        return results;
    }
    
    // Get system status
    json getSystemStatus() {
        json status;
        status["totalVotes"] = votes.size();
        status["hashChainLength"] = hashChain.size();
        status["merkleRootHash"] = merkleRoot ? merkleRoot->hash : "No votes yet";
        status["lastBlockHash"] = hashChain.empty() ? "No blocks" : hashChain.back().blockHash;
        
        return status;
    }
    
    // Rebuild Merkle tree
    void rebuildMerkleTree() {
        cleanupMerkleTree(merkleRoot);
        
        if (votes.empty()) {
            merkleRoot = nullptr;
            return;
        }
        
        std::vector<std::string> voteHashes;
        for (const auto& vote : votes) {
            voteHashes.push_back(vote.voteHash);
        }
        
        merkleRoot = buildMerkleTree(voteHashes);
    }
    
    // Print hash chain
    void printHashChain() {
        std::cout << "\n=== Hash Chain ===" << std::endl;
        for (size_t i = 0; i < hashChain.size(); i++) {
            const auto& block = hashChain[i];
            cout << "Block " << i + 1 << ":" << std::endl;
            cout << "  Previous Hash: " << block.previousHash << std::endl;
            cout << "  Vote Hash: " << block.voteHash << std::endl;
            cout << "  Block Hash: " << block.blockHash << std::endl;
            cout << "  Nonce: " << block.nonce << std::endl;
            cout << "  Timestamp: " << block.timestamp << std::endl;
            cout << std::endl;
        }
    }
    
    // Print Merkle tree (in-order traversal)
    void printMerkleTree(MerkleNode* node, int depth = 0) {
        if (node) {
            printMerkleTree(node->left, depth + 1);
            std::cout << std::string(depth * 2, ' ') << "Hash: " << node->hash << std::endl;
            printMerkleTree(node->right, depth + 1);
        }
    }
    
    void printMerkleTree() {
        std::cout << "\n=== Merkle Tree ===" << std::endl;
        if (merkleRoot) {
            printMerkleTree(merkleRoot);
        } else {
            std::cout << "No votes yet" << std::endl;
        }
    }
};

// Simple HTTP response function (for CGI compatibility)
void sendHTTPResponse(const std::string& contentType, const std::string& body) {
    cout << "Content-Type: " << contentType << "\r\n";
    cout << "Access-Control-Allow-Origin: *\r\n";
    cout << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    cout << "Access-Control-Allow-Headers: Content-Type\r\n";
    cout << "\r\n";
    cout << body;
}

int main() {
    EVotingSystem votingSystem;
    cout << "=== E-Voting System Backend (Interactive Demo) ===" << endl;

    while (true) {
        cout << "\nMenu:\n";
        cout << "1. Submit Vote\n";
        cout << "2. Verify Vote\n";
        cout << "3. Show Results\n";
        cout << "4. Exit\n";
        cout << "Enter your choice: ";
        int choice;
        cin >> choice;
        cin.ignore(); // To clear newline

        if (choice == 1) {
            string voterId, voterName, voterEmail, constituency, candidate;
            cout << "Enter Voter ID: ";
            getline(cin, voterId);
            cout << "Enter Name: ";
            getline(cin, voterName);
            cout << "Enter Email: ";
            getline(cin, voterEmail);
            cout << "Enter Constituency: ";
            getline(cin, constituency);
            cout << "Enter Candidate (candidate1/candidate2/candidate3): ";
            getline(cin, candidate);

            bool success = votingSystem.submitVote(voterId, voterName, voterEmail, constituency, candidate);
            if (success) {
                cout << "Vote submitted successfully!\n";
            } else {
                cout << "Vote submission failed (maybe duplicate Voter ID).\n";
            }
        } else if (choice == 2) {
            string voterId;
            cout << "Enter Voter ID to verify: ";
            getline(cin, voterId);
            json result = votingSystem.verifyVote(voterId);
            cout << result.dump(2) << endl;
        } else if (choice == 3) {
            json results = votingSystem.getElectionResults();
            cout << results.dump(2) << endl;
        } else if (choice == 4) {
            cout << "Exiting...\n";
            break;
        } else {
            cout << "Invalid choice. Try again.\n";
        }
    }

    return 0;
}