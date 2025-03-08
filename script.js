// Secure Password Generator
// Enhanced cybersecurity features with entropy calculation and password strength estimation

// Character sets for password generation with expanded special characters for higher entropy
const characterSets = {
    special: '!@#$%^&*()_+~`|}{[]:;?><,./-=',
    numeric: '0123456789',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    ambiguous: 'Il1O0',  // Characters that can be visually confused
    similar: '{}[]()|\\/\'"`~,;:.<>'  // Similar appearing characters
  };
  
  // Password strength thresholds
  const strengthThresholds = {
    weak: 40,
    medium: 60,
    strong: 80,
    veryStrong: 100
  };
  
  // Configuration options
  let config = {
    minLength: 8,
    maxLength: 128,
    defaultLength: 16,
    defaultOptions: {
      includeSpecial: true,
      includeNumeric: true,
      includeLowercase: true,
      includeUppercase: true,
      excludeAmbiguous: false,
      excludeSimilar: false,
      requireAllTypes: true
    }
  };
  
  // DOM element references
  const elements = {
    generateBtn: document.querySelector('#generate'),
    passwordText: document.querySelector('#password'),
    strengthMeter: document.querySelector('#strength-meter'),
    strengthText: document.querySelector('#strength-text'),
    passwordLength: document.querySelector('#password-length'),
    lengthValue: document.querySelector('#length-value'),
    copyBtn: document.querySelector('#copy'),
    options: {
      special: document.querySelector('#include-special'),
      numeric: document.querySelector('#include-numeric'),
      lowercase: document.querySelector('#include-lowercase'),
      uppercase: document.querySelector('#include-uppercase'),
      ambiguous: document.querySelector('#exclude-ambiguous'),
      similar: document.querySelector('#exclude-similar'),
      allTypes: document.querySelector('#require-all-types')
    },
    advancedToggle: document.querySelector('#advanced-toggle'),
    advancedOptions: document.querySelector('#advanced-options'),
    errorMessage: document.querySelector('#error-message')
  };
  
  // Initialize the application
  function initializeApp() {
    // Set default values
    elements.passwordLength.value = config.defaultLength;
    elements.lengthValue.textContent = config.defaultLength;
    
    // Set default checkboxes
    Object.keys(elements.options).forEach(key => {
      if (elements.options[key]) {
        if (key === 'ambiguous' || key === 'similar') {
          elements.options[key].checked = config.defaultOptions[`exclude${key.charAt(0).toUpperCase() + key.slice(1)}`];
        } else if (key === 'allTypes') {
          elements.options[key].checked = config.defaultOptions.requireAllTypes;
        } else {
          elements.options[key].checked = config.defaultOptions[`include${key.charAt(0).toUpperCase() + key.slice(1)}`];
        }
      }
    });
  
    // Add event listeners
    elements.generateBtn.addEventListener('click', writePassword);
    elements.copyBtn.addEventListener('click', copyPassword);
    elements.passwordLength.addEventListener('input', updateLengthDisplay);
    elements.advancedToggle.addEventListener('click', toggleAdvancedOptions);
    
    // Initialize with a default password
    writePassword();
  }
  
  // Generate a random element from an array
  function getRandomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }
  
  // Get a cryptographically secure random integer between min and max (inclusive)
  function getSecureRandomInt(min, max) {
    const range = max - min + 1;
    const byteLength = Math.ceil(Math.log2(range) / 8);
    const maxValue = Math.pow(256, byteLength);
    const maxValidValue = maxValue - (maxValue % range);
    
    let randomValue;
    do {
      const randomBytes = new Uint8Array(byteLength);
      window.crypto.getRandomValues(randomBytes);
      
      randomValue = 0;
      for (let i = 0; i < byteLength; i++) {
        randomValue = (randomValue << 8) + randomBytes[i];
      }
    } while (randomValue >= maxValidValue);
    
    return min + (randomValue % range);
  }
  
  // Fisher-Yates shuffle algorithm for arrays
  function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = getSecureRandomInt(0, i);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
  }
  
  // Calculate password entropy
  function calculateEntropy(password, possibleCharacters) {
    const length = password.length;
    const poolSize = possibleCharacters.length;
    // Entropy = log2(poolSize^length) = length * log2(poolSize)
    return length * (Math.log(poolSize) / Math.log(2));
  }
  
  // Estimate password strength based on entropy and other factors
  function estimatePasswordStrength(password, options) {
    let strength = 0;
    
    // Calculate base entropy
    let possibleCharacters = '';
    if (options.includeSpecial) possibleCharacters += characterSets.special;
    if (options.includeNumeric) possibleCharacters += characterSets.numeric;
    if (options.includeLowercase) possibleCharacters += characterSets.lowercase;
    if (options.includeUppercase) possibleCharacters += characterSets.uppercase;
    
    // Remove excluded characters
    if (options.excludeAmbiguous) {
      for (const char of characterSets.ambiguous) {
        possibleCharacters = possibleCharacters.replace(char, '');
      }
    }
    
    if (options.excludeSimilar) {
      for (const char of characterSets.similar) {
        possibleCharacters = possibleCharacters.replace(char, '');
      }
    }
    
    // Calculate entropy
    const entropy = calculateEntropy(password, possibleCharacters);
    
    // Base score from entropy (0-100)
    strength = Math.min(100, (entropy / 100) * 70);
    
    // Check for character variety (up to +20)
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);
    
    const varietyCount = [hasLower, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;
    strength += varietyCount * 5;
    
    // Check for patterns/sequences that weaken passwords (up to -20)
    // Repeated characters
    const repeatedChars = password.match(/(.)\1{2,}/g);
    if (repeatedChars) {
      strength -= repeatedChars.length * 5;
    }
    
    // Common sequences
    const sequences = ['abcdef', '123456', 'qwerty'];
    for (const seq of sequences) {
      if (password.toLowerCase().includes(seq)) {
        strength -= 10;
        break;
      }
    }
    
    return Math.max(0, Math.min(100, strength));
  }
  
  // Update the password strength meter and text
  function updateStrengthIndicator(password, options) {
    const strength = estimatePasswordStrength(password, options);
    
    // Update the progress bar
    elements.strengthMeter.value = strength;
    
    // Update the text description
    let strengthDescription;
    let strengthClass;
    
    if (strength < strengthThresholds.weak) {
      strengthDescription = 'Weak';
      strengthClass = 'weak';
    } else if (strength < strengthThresholds.medium) {
      strengthDescription = 'Medium';
      strengthClass = 'medium';
    } else if (strength < strengthThresholds.strong) {
      strengthDescription = 'Strong';
      strengthClass = 'strong';
    } else {
      strengthDescription = 'Very Strong';
      strengthClass = 'very-strong';
    }
    
    elements.strengthText.textContent = strengthDescription;
    
    // Remove all strength classes
    elements.strengthText.classList.remove('weak', 'medium', 'strong', 'very-strong');
    // Add the current strength class
    elements.strengthText.classList.add(strengthClass);
    
    // Set the color of the meter based on strength
    elements.strengthMeter.className = strengthClass;
  }
  
  // Get password generation options from the UI
  function getPasswordOptions() {
    // Get password length from the range input
    const length = parseInt(elements.passwordLength.value);
    
    // Validate length
    if (isNaN(length)) {
      showError('Password length must be a number');
      return null;
    }
    
    if (length < config.minLength) {
      showError(`Password length must be at least ${config.minLength} characters`);
      return null;
    }
    
    if (length > config.maxLength) {
      showError(`Password length must be less than ${config.maxLength} characters`);
      return null;
    }
    
    // Get character type options
    const options = {
      includeSpecial: elements.options.special.checked,
      includeNumeric: elements.options.numeric.checked,
      includeLowercase: elements.options.lowercase.checked,
      includeUppercase: elements.options.uppercase.checked,
      excludeAmbiguous: elements.options.ambiguous.checked,
      excludeSimilar: elements.options.similar.checked,
      requireAllTypes: elements.options.allTypes.checked
    };
    
    // Validate that at least one character type is selected
    if (!options.includeSpecial && !options.includeNumeric && 
        !options.includeLowercase && !options.includeUppercase) {
      showError('Must select at least one character type');
      return null;
    }
    
    hideError();
    return { length, ...options };
  }
  
  // Generate a password based on user options
  function generatePassword() {
    const options = getPasswordOptions();
    if (!options) return '';
    
    // Determine which character sets to include
    let availableChars = '';
    const guaranteedChars = [];
    
    if (options.includeSpecial) {
      let specialChars = characterSets.special;
      if (options.excludeSimilar) {
        for (const char of characterSets.similar) {
          specialChars = specialChars.replace(char, '');
        }
      }
      availableChars += specialChars;
      if (options.requireAllTypes && specialChars.length > 0) {
        guaranteedChars.push(specialChars[getSecureRandomInt(0, specialChars.length - 1)]);
      }
    }
    
    if (options.includeNumeric) {
      let numericChars = characterSets.numeric;
      if (options.excludeAmbiguous) {
        for (const char of characterSets.ambiguous) {
          if (numericChars.includes(char)) {
            numericChars = numericChars.replace(char, '');
          }
        }
      }
      availableChars += numericChars;
      if (options.requireAllTypes && numericChars.length > 0) {
        guaranteedChars.push(numericChars[getSecureRandomInt(0, numericChars.length - 1)]);
      }
    }
    
    if (options.includeLowercase) {
      let lowerChars = characterSets.lowercase;
      if (options.excludeAmbiguous) {
        for (const char of characterSets.ambiguous) {
          if (lowerChars.includes(char)) {
            lowerChars = lowerChars.replace(char, '');
          }
        }
      }
      availableChars += lowerChars;
      if (options.requireAllTypes && lowerChars.length > 0) {
        guaranteedChars.push(lowerChars[getSecureRandomInt(0, lowerChars.length - 1)]);
      }
    }
    
    if (options.includeUppercase) {
      let upperChars = characterSets.uppercase;
      if (options.excludeAmbiguous) {
        for (const char of characterSets.ambiguous) {
          if (upperChars.includes(char)) {
            upperChars = upperChars.replace(char, '');
          }
        }
      }
      availableChars += upperChars;
      if (options.requireAllTypes && upperChars.length > 0) {
        guaranteedChars.push(upperChars[getSecureRandomInt(0, upperChars.length - 1)]);
      }
    }
    
    // Check if we have at least one character available
    if (availableChars.length === 0) {
      showError('No characters available with current options');
      return '';
    }
    
    // Build the password
    let passwordChars = [];
    
    // Add guaranteed characters first if required
    if (options.requireAllTypes) {
      passwordChars = [...guaranteedChars];
    }
    
    // Fill the rest with random characters
    while (passwordChars.length < options.length) {
      const randomIndex = getSecureRandomInt(0, availableChars.length - 1);
      passwordChars.push(availableChars[randomIndex]);
    }
    
    // If we have too many characters (due to guaranteed chars), trim the excess
    if (passwordChars.length > options.length) {
      passwordChars = passwordChars.slice(0, options.length);
    }
    
    // Shuffle the array to make sure guaranteed characters aren't always at the beginning
    passwordChars = shuffleArray(passwordChars);
    
    // Join the characters into a string
    const password = passwordChars.join('');
    
    // Update the strength indicator
    updateStrengthIndicator(password, options);
    
    return password;
  }
  
  // Write the generated password to the page
  function writePassword() {
    const password = generatePassword();
    elements.passwordText.value = password;
    
    // Enable or disable the copy button based on whether there's a password
    elements.copyBtn.disabled = !password;
  }
  
  // Copy the password to clipboard
  function copyPassword() {
    const password = elements.passwordText.value;
    if (!password) return;
    
    // Use the Clipboard API if available, fall back to execCommand
    if (navigator.clipboard) {
      navigator.clipboard.writeText(password)
        .then(() => {
          showCopySuccess();
        })
        .catch(err => {
          console.error('Could not copy text: ', err);
          fallbackCopyTextToClipboard(password);
        });
    } else {
      fallbackCopyTextToClipboard(password);
    }
  }
  
  // Fallback method for copying to clipboard
  function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    
    // Make the textarea out of viewport
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
      const successful = document.execCommand('copy');
      if (successful) {
        showCopySuccess();
      } else {
        console.error('Fallback: Unable to copy');
      }
    } catch (err) {
      console.error('Fallback: Oops, unable to copy', err);
    }
    
    document.body.removeChild(textArea);
  }
  
  // Show a success message when password is copied
  function showCopySuccess() {
    const button = elements.copyBtn;
    const originalText = button.textContent;
    
    button.textContent = 'Copied!';
    button.classList.add('success');
    
    setTimeout(() => {
      button.textContent = originalText;
      button.classList.remove('success');
    }, 2000);
  }
  
  // Update the length display when the slider changes
  function updateLengthDisplay() {
    elements.lengthValue.textContent = elements.passwordLength.value;
    // Generate a new password when the length changes
    writePassword();
  }
  
  // Toggle advanced options visibility
  function toggleAdvancedOptions() {
    elements.advancedOptions.classList.toggle('show');
    const isShowing = elements.advancedOptions.classList.contains('show');
    elements.advancedToggle.textContent = isShowing ? 'Hide Advanced Options' : 'Show Advanced Options';
  }
  
  // Show an error message
  function showError(message) {
    elements.errorMessage.textContent = message;
    elements.errorMessage.classList.add('show');
  }
  
  // Hide the error message
  function hideError() {
    elements.errorMessage.textContent = '';
    elements.errorMessage.classList.remove('show');
  }
  
  // Initialize the app when the DOM is loaded
  document.addEventListener('DOMContentLoaded', initializeApp);