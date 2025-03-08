# Secure Password Generator

## 🔐 Overview

A modern, enterprise-grade password generator with advanced cybersecurity features. This application creates cryptographically secure passwords with detailed strength analysis and entropy calculation.

## 🚀 Features

- **Cryptographic Security**: Uses Web Cryptography API for true randomness
- **Entropy Calculation**: Provides mathematical measurement of password strength
- **Customizable Options**: Configure length, character sets, and special requirements
- **Visual Strength Meter**: Real-time feedback on password security
- **Advanced Controls**: Exclude ambiguous characters, require specific character types
- **Mobile Responsive**: Works seamlessly across all device sizes
- **Accessibility**: Built with a11y best practices for universal usability
- **Zero Server Dependency**: All computation happens client-side for maximum privacy

## 🧰 Technologies Used

- **JavaScript**: ES6+ features with strict security practices
- **CSS3**: Modern design with CSS variables and flexbox/grid
- **HTML5**: Semantic markup with accessibility features
- **Web Cryptography API**: For cryptographically secure random number generation
- **Font Awesome**: For intuitive iconography
- **Responsive Design**: Mobile-first approach for all screen sizes

## 🔍 Security Features

- Implements NIST [SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) guidelines for password security
- Uses cryptographically secure random number generation (CSPRNG)
- Calculates and displays password entropy for objective strength measurement
- Enforces minimum security requirements with real-time validation
- Provides educational information about password best practices

## 📊 Password Strength Analysis

The application uses multiple factors to determine password strength:

1. **Entropy Calculation**: Mathematical measurement of randomness
2. **Character Diversity**: Analysis of character type distribution
3. **Pattern Detection**: Identification of common sequences or repetitions
4. **Length Assessment**: Evaluation based on password length

## 🚦 Getting Started

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Installation
1. Clone the repository
```bash
git clone https://github.com/freddricklogan/secure-password-generator.git