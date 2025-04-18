# Secure Data Encryption App - Technical Stack

## Core Technologies

### Mobile Development
- **Framework**: React Native + TypeScript
- **Build System**: Expo SDK
- **Navigation**: Expo Router
- **UI Components**: React Native Paper
- **State Management**: Redux Toolkit

### Backend Services
- **Authentication**: Supabase Auth
  - OTP verification
  - Session management
  - Rate limiting
- **Cloud Storage**: 
  - Google Drive API
  - iCloud API
  - AWS S3

## Security Implementation

### Cryptography
| Component | Technology | Purpose |
|-----------|------------|----------|
| Data Encryption | AES-256-GCM-SIV | Secure data encryption |
| Password Hashing | Argon2id | Key derivation |
| Biometric Processing | HMAC-SHA512 | Fingerprint hashing |
| Key Exchange | X25519 | Secure key exchange |

### Data Processing
- **Compression**: Zlib/Gzip
- **Transport Security**: TLS 1.3
- **API Authentication**: OAuth 2.0 + JWT
- **Optional**: Mutual TLS (mTLS)

## Infrastructure

### Security Services
- **DDoS Protection**: Cloudflare
- **API Security**: AWS Shield
- **WAF**: Cloudflare WAF

### DevOps
- **CI/CD**: GitHub Actions
- **Monitoring**: Sentry
- **Analytics**: Mixpanel

## Data Flow

### Upload Process 
# Secure Data Encryption Application - Overview

## Objective
The goal of this application is to securely encrypt user data before uploading it to cloud services, following the highest security standards. The data will be encrypted at runtime using a combination of the user's fingerprint and password, and then compressed to minimize storage requirements.

## Features
- **Secure Data Upload to Cloud**: Upload encrypted and compressed data to cloud storage via API
- **Runtime Encryption and Compression**: Encrypt data using fingerprint and password keys, then compress
- **One-Time Password (OTP) Authentication**: Secure login process with OTP verification
- **Session Management**: Single active session per user with timeout functionality
- **No User Data Storage**: Zero persistent storage of personal data except minimal session info

## Application Flow

### 1. Login Process
- User provides email/iCloud ID
- Server generates and sends OTP
- User verifies OTP
- Session created with single-session enforcement
- Rate limiting prevents brute-force attempts
- All communication over HTTPS

### 2. Storage Configuration
- User specifies cloud storage destination
- App validates storage API access

### 3. Data Processing
- Data handled locally on device
- No server-side data storage
- Minimal session data retained

### 4. Security Implementation
#### Encryption
- Runtime key generation using:
  - Biometric data (fingerprint)
  - User password
- Encryption stack:
  - HMAC-SHA512 for biometric processing
  - Argon2id for password hashing
  - AES-256-GCM-SIV for data encryption

#### Compression
- Post-encryption compression
- Industry-standard algorithms (ZIP/GZIP)
- Integrity preservation

### 5. Cloud Operations
- Secure API-based upload
- No persistent key storage
- Runtime-only key lifecycle

### 6. Session Security
- Single active session policy
- OTP-based authentication
- Automatic session expiration

### 7. Data Retrieval
1. Download encrypted data
2. Decompress data
3. Runtime decryption
4. Secure memory cleanup

## Security Framework Compliance

### OWASP Mobile Security
- Secure credential storage
- Strong encryption (AES-256)
- HTTPS communication
- Input validation
- Secure API integration

### MITRE ATT&CK
- Pre-upload encryption
- Multi-layer security architecture
- Access monitoring and control

### Key Management
- Runtime-only key generation
- Combined biometric/password key derivation
- Zero persistent key storage

### Authentication
- Email/iCloud OTP delivery
- Single-use OTP tokens
- Rate-limited verification
