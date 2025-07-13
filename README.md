# 🗳️ Secure E-Voting System

A modern, secure e-voting system with **transparent verification** using **Merkle Trees** and **Hash Chains**. Built with HTML/CSS/JS frontend and C++ backend.

![E-Voting System](https://img.shields.io/badge/Status-Complete-brightgreen)
![Frontend](https://img.shields.io/badge/Frontend-HTML%2FCSS%2FJS-blue)
![Backend](https://img.shields.io/badge/Backend-C%2B%2B-orange)
![Security](https://img.shields.io/badge/Security-Merkle%20Tree%20%2B%20Hash%20Chain-red)

## ✨ Features

### 🎨 Frontend (HTML/CSS/JS)
- **Modern UI Design** - Beautiful, responsive interface
- **Tab-based Navigation** - Cast Vote, Verify Vote, Live Results
- **Real-time Validation** - Form validation with instant feedback
- **Interactive Candidate Selection** - Click-to-select candidate cards
- **Live Results Dashboard** - Real-time election results with progress bars
- **Mobile Responsive** - Works perfectly on all devices

### 🔒 Backend (C++)
- **Merkle Tree Implementation** - Efficient vote integrity verification
- **Hash Chain (Blockchain-like)** - Tamper-evident vote storage
- **SHA-256 Cryptography** - Secure vote hashing
- **Duplicate Vote Prevention** - Prevents double voting
- **Real-time Verification** - Instant vote verification system
- **JSON API** - Easy integration with frontend

## 🏗️ Architecture

```
┌─────────────────┐    HTTP/JSON    ┌─────────────────┐
│   Frontend      │ ◄─────────────► │    Backend      │
│   (HTML/CSS/JS) │                 │     (C++)       │
└─────────────────┘                 └─────────────────┘
         │                                    │
         │                                    │
    User Interface                    Data Structures
    • Voting Form                     • Merkle Tree
    • Verification                    • Hash Chain
    • Live Results                    • Vote Storage
```

## 🚀 Quick Start

### 1. Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Open in browser
# Simply open index.html in your web browser
# Or use a local server:
python -m http.server 8000
# Then visit: http://localhost:8000
```

### 2. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential cmake libssl-dev nlohmann-json3-dev

# Build the project
mkdir build && cd build
cmake ..
make

# Run the backend
./voting_system
```

## 📁 Project Structure

```
e-voting-system/
├── frontend/
│   ├── index.html          # Main voting interface
│   ├── style.css           # Modern styling
│   └── script.js           # Interactive functionality
├── backend/
│   ├── main.cpp            # Core voting system logic
│   ├── CMakeLists.txt      # Build configuration
│   └── README.md           # Backend documentation
└── README.md               # This file
```

## 🎯 How It Works

### 1. **Vote Casting Process**
```
User Input → Frontend Validation → Backend Processing → Hash Generation → Merkle Tree Update → Hash Chain Addition
```

### 2. **Vote Verification Process**
```
Voter ID → Backend Lookup → Hash Validation → Chain Verification → Merkle Tree Check → Verification Result
```

### 3. **Security Features**
- **Cryptographic Hashing**: Each vote gets a unique SHA-256 hash
- **Merkle Tree**: Efficient verification of vote integrity
- **Hash Chain**: Tamper-evident storage with proof of work
- **Duplicate Prevention**: One vote per voter ID

## 🎨 Frontend Features

### Voting Interface
- ✅ Voter ID validation (8-12 characters)
- ✅ Name validation (letters and spaces only)
- ✅ Email validation
- ✅ Constituency selection
- ✅ Interactive candidate cards
- ✅ Vote confirmation checkbox
- ✅ Real-time form validation

### Verification Interface
- ✅ Voter ID lookup
- ✅ Detailed verification results
- ✅ Hash display for transparency
- ✅ Success/error messaging

### Live Results
- ✅ Real-time vote counts
- ✅ Percentage calculations
- ✅ Progress bar visualization
- ✅ Auto-updating every 30 seconds

## 🔧 Backend Features

### Data Structures
```cpp
// Vote Structure
struct Vote {
    string voterId, voterName, voterEmail;
    string constituency, candidate;
    string timestamp, voteHash, previousHash;
};

// Merkle Tree Node
struct MerkleNode {
    string hash;
    MerkleNode* left, *right;
};

// Hash Chain Block
struct HashBlock {
    string blockHash, previousHash, voteHash;
    string timestamp;
    int nonce;
};
```

### Core Functions
- `submitVote()` - Process and store votes
- `verifyVote()` - Verify vote integrity
- `getElectionResults()` - Get live results
- `getSystemStatus()` - System health check

## 🔐 Security Implementation

### 1. **Merkle Tree**
```cpp
// Efficient vote verification
MerkleNode* buildMerkleTree(vector<string> hashes) {
    // Builds binary tree of vote hashes
    // Single root hash represents all votes
    // Quick integrity verification
}
```

### 2. **Hash Chain**
```cpp
// Tamper-evident storage
void addToHashChain(string voteHash) {
    // Each block linked to previous
    // Proof of work (4 leading zeros)
    // Immutable vote history
}
```

### 3. **Cryptographic Hashing**
```cpp
// SHA-256 vote hashing
string generateSHA256(string input) {
    // Unique hash for each vote
    // Tamper detection
    // Cryptographic security
}
```

## 📊 Sample Output

### Frontend Demo
- **Voting Form**: Clean, modern interface with validation
- **Verification**: Detailed results with hash display
- **Live Results**: Real-time updates with progress bars

### Backend Demo
```
=== E-Voting System Backend ===
Vote submitted successfully for voter: VOTER001
Vote Hash: a1b2c3d4e5f6...
Block Hash: 0000f8a7b9c2...

System Status: {
  "totalVotes": 4,
  "hashChainLength": 4,
  "merkleRootHash": "abc123...",
  "lastBlockHash": "0000f8a7b9c2..."
}
```

## 🛠️ Technology Stack

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Modern styling with gradients and animations
- **JavaScript (ES6+)** - Interactive functionality
- **Font Awesome** - Icons
- **Responsive Design** - Mobile-first approach

### Backend
- **C++17** - High-performance backend
- **OpenSSL** - Cryptographic functions
- **nlohmann/json** - JSON handling
- **CMake** - Build system
- **STL** - Standard data structures

## 🎯 Use Cases

1. **Educational Institutions** - Student council elections
2. **Organizations** - Board member elections
3. **Communities** - Local community voting
4. **Research** - Blockchain/security studies
5. **Prototyping** - E-voting system development

## 🔮 Future Enhancements

### Frontend
- [ ] Dark/Light theme toggle
- [ ] Multi-language support
- [ ] Advanced analytics dashboard
- [ ] Real-time notifications
- [ ] Offline capability

### Backend
- [ ] Database integration (SQLite/PostgreSQL)
- [ ] REST API endpoints
- [ ] WebSocket support
- [ ] Admin panel
- [ ] Vote encryption
- [ ] Multi-constituency support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is for **educational purposes**. Use responsibly in production environments.

## 🙏 Acknowledgments

- **Merkle Tree** concept by Ralph Merkle
- **Hash Chain** inspired by blockchain technology
- **OpenSSL** for cryptographic functions
- **Font Awesome** for beautiful icons

---

**Built with ❤️ for secure, transparent voting**

*This system demonstrates modern web development and cryptographic security concepts.* 