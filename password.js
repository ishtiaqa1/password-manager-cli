const prompt = require('prompt-sync')();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, 'passwords.json');
const MASTER_FILE = path.join(__dirname, 'master.json');

const ALGORITHM = 'aes-256-cbc';
const SALT = 'password-manager-salt';

class PasswordManager {
    constructor() {
        this.masterPassword = null;
        this.passwords = [];
        this.isAuthenticated = false;
    }

    hashPassword(password) {
        return crypto.createHash('sha256').update(password).digest('hex');
    }

    encrypt(text, masterPassword) {
        const key = crypto.scryptSync(masterPassword, SALT, 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }

    decrypt(encryptedText, masterPassword) {
        try {
            const key = crypto.scryptSync(masterPassword, SALT, 32);
            const parts = encryptedText.split(':');
            const iv = Buffer.from(parts[0], 'hex');
            const encrypted = parts[1];
            const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            return null;
        }
    }

    setupMasterPassword() {
        console.log('\n=== FIRST TIME SETUP ===');
        console.log('Create a master password to secure your vault.');
        console.log('⚠️  DO NOT FORGET THIS PASSWORD - It cannot be recovered!\n');
        
        const password = prompt('Enter master password: ', { echo: '*' });
        const confirm = prompt('Confirm master password: ', { echo: '*' });

        if (password !== confirm) {
            console.log('❌ Passwords do not match!');
            return false;
        }

        if (password.length < 6) {
            console.log('❌ Master password must be at least 6 characters!');
            return false;
        }

        const hashed = this.hashPassword(password);
        fs.writeFileSync(MASTER_FILE, JSON.stringify({ hash: hashed }));
        console.log('✅ Master password created successfully!');
        return true;
    }

    authenticate() {
        if (!fs.existsSync(MASTER_FILE)) {
            if (!this.setupMasterPassword()) {
                return false;
            }
        }

        const masterData = JSON.parse(fs.readFileSync(MASTER_FILE, 'utf8'));
        
        let attempts = 3;
        while (attempts > 0) {
            const password = prompt('\nEnter master password: ', { echo: '*' });
            const hashed = this.hashPassword(password);

            if (hashed === masterData.hash) {
                this.masterPassword = password;
                this.isAuthenticated = true;
                this.loadPasswords();
                console.log('✅ Authentication successful!\n');
                return true;
            }

            attempts--;
            if (attempts > 0) {
                console.log(`❌ Incorrect password. ${attempts} attempt(s) remaining.`);
            }
        }

        console.log('❌ Too many failed attempts. Exiting...');
        return false;
    }

    loadPasswords() {
        if (fs.existsSync(DATA_FILE)) {
            const data = fs.readFileSync(DATA_FILE, 'utf8');
            this.passwords = JSON.parse(data);
        } else {
            this.passwords = [];
        }
    }

    savePasswords() {
        fs.writeFileSync(DATA_FILE, JSON.stringify(this.passwords, null, 2));
    }

    generatePassword(length = 16) {
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        const allChars = lowercase + uppercase + numbers + symbols;

        let password = '';
        password += lowercase[Math.floor(Math.random() * lowercase.length)];
        password += uppercase[Math.floor(Math.random() * uppercase.length)];
        password += numbers[Math.floor(Math.random() * numbers.length)];
        password += symbols[Math.floor(Math.random() * symbols.length)];

        for (let i = password.length; i < length; i++) {
            password += allChars[Math.floor(Math.random() * allChars.length)];
        }

        return password.split('').sort(() => Math.random() - 0.5).join('');
    }

    checkPasswordStrength(password) {
        let strength = 0;
        const checks = {
            length: password.length >= 12,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /[0-9]/.test(password),
            symbols: /[^A-Za-z0-9]/.test(password)
        };

        strength = Object.values(checks).filter(Boolean).length;

        if (strength <= 2) return '🔴 Weak';
        if (strength <= 3) return '🟡 Medium';
        if (strength <= 4) return '🟢 Strong';
        return '🟢 Very Strong';
    }

    addPassword() {
        console.log('\n=== ADD NEW PASSWORD ===');
        
        const service = prompt('Service/Website name: ');
        if (!service) {
            console.log('❌ Service name is required!');
            return;
        }

        const username = prompt('Username/Email: ');
        const category = prompt('Category (optional): ') || 'General';

        console.log('\n1. Enter password manually');
        console.log('2. Generate strong password');
        const choice = prompt('Choose option (1-2): ');

        let password;
        if (choice === '2') {
            const length = prompt('Password length (default 16): ') || '16';
            password = this.generatePassword(parseInt(length));
            console.log(`\n🔑 Generated password: ${password}`);
            console.log(`   Strength: ${this.checkPasswordStrength(password)}`);
        } else {
            password = prompt('Password: ', { echo: '*' });
            console.log(`   Strength: ${this.checkPasswordStrength(password)}`);
        }

        const url = prompt('URL (optional): ') || '';
        const notes = prompt('Notes (optional): ') || '';

        const encryptedPassword = this.encrypt(password, this.masterPassword);

        const entry = {
            id: Date.now(),
            service,
            username,
            password: encryptedPassword,
            category,
            url,
            notes,
            createdAt: new Date().toISOString()
        };

        this.passwords.push(entry);
        this.savePasswords();
        console.log('✅ Password saved successfully!');
    }

    viewPasswords() {
        if (this.passwords.length === 0) {
            console.log('\n📭 No passwords stored yet.');
            return;
        }

        console.log('\n=== YOUR PASSWORDS ===\n');
        this.passwords.forEach((entry, index) => {
            console.log(`${index + 1}. ${entry.service}`);
            console.log(`   Username: ${entry.username}`);
            console.log(`   Category: ${entry.category}`);
            if (entry.url) console.log(`   URL: ${entry.url}`);
            console.log(`   Created: ${new Date(entry.createdAt).toLocaleDateString()}`);
            console.log('');
        });

        const choice = prompt('Enter number to view password (or press Enter to go back): ');
        if (choice && !isNaN(choice)) {
            const index = parseInt(choice) - 1;
            if (index >= 0 && index < this.passwords.length) {
                this.viewPasswordDetail(this.passwords[index]);
            }
        }
    }

    viewPasswordDetail(entry) {
        console.log('\n=== PASSWORD DETAILS ===');
        console.log(`Service: ${entry.service}`);
        console.log(`Username: ${entry.username}`);
        console.log(`Category: ${entry.category}`);
        if (entry.url) console.log(`URL: ${entry.url}`);
        if (entry.notes) console.log(`Notes: ${entry.notes}`);
        
        const decrypted = this.decrypt(entry.password, this.masterPassword);
        if (decrypted) {
            console.log(`Password: ${decrypted}`);
            console.log(`Strength: ${this.checkPasswordStrength(decrypted)}`);
        } else {
            console.log('❌ Failed to decrypt password');
        }
        
        prompt('\nPress Enter to continue...');
    }

    searchPasswords() {
        console.log('\n=== SEARCH PASSWORDS ===');
        const query = prompt('Search by service name or category: ').toLowerCase();

        const results = this.passwords.filter(entry => 
            entry.service.toLowerCase().includes(query) ||
            entry.category.toLowerCase().includes(query) ||
            entry.username.toLowerCase().includes(query)
        );

        if (results.length === 0) {
            console.log('❌ No passwords found.');
            return;
        }

        console.log(`\n✅ Found ${results.length} result(s):\n`);
        results.forEach((entry, index) => {
            console.log(`${index + 1}. ${entry.service} (${entry.category})`);
            console.log(`   Username: ${entry.username}`);
            console.log('');
        });

        const choice = prompt('Enter number to view password (or press Enter to go back): ');
        if (choice && !isNaN(choice)) {
            const index = parseInt(choice) - 1;
            if (index >= 0 && index < results.length) {
                this.viewPasswordDetail(results[index]);
            }
        }
    }

    deletePassword() {
        if (this.passwords.length === 0) {
            console.log('\n📭 No passwords to delete.');
            return;
        }

        console.log('\n=== DELETE PASSWORD ===\n');
        this.passwords.forEach((entry, index) => {
            console.log(`${index + 1}. ${entry.service} (${entry.username})`);
        });

        const choice = prompt('\nEnter number to delete (or 0 to cancel): ');
        const index = parseInt(choice) - 1;

        if (choice === '0') {
            console.log('Cancelled.');
            return;
        }

        if (index >= 0 && index < this.passwords.length) {
            const entry = this.passwords[index];
            const confirm = prompt(`⚠️  Delete "${entry.service}"? This cannot be undone. (yes/no): `);
            
            if (confirm.toLowerCase() === 'yes') {
                this.passwords.splice(index, 1);
                this.savePasswords();
                console.log('✅ Password deleted successfully!');
            } else {
                console.log('Cancelled.');
            }
        } else {
            console.log('❌ Invalid selection.');
        }
    }

    showStats() {
        console.log('\n=== VAULT STATISTICS ===');
        console.log(`Total passwords: ${this.passwords.length}`);
        
        if (this.passwords.length > 0) {
            const categories = {};
            this.passwords.forEach(entry => {
                categories[entry.category] = (categories[entry.category] || 0) + 1;
            });

            console.log('\nPasswords by category:');
            Object.entries(categories).forEach(([cat, count]) => {
                console.log(`  ${cat}: ${count}`);
            });

            let weakCount = 0;
            this.passwords.forEach(entry => {
                const decrypted = this.decrypt(entry.password, this.masterPassword);
                if (decrypted) {
                    const strength = this.checkPasswordStrength(decrypted);
                    if (strength.includes('Weak')) weakCount++;
                }
            });

            if (weakCount > 0) {
                console.log(`\n⚠️  Warning: ${weakCount} weak password(s) detected!`);
            }
        }
        
        prompt('\nPress Enter to continue...');
    }

    showMenu() {
        console.clear();
        console.log('╔════════════════════════════════════╗');
        console.log('║     PASSWORD MANAGER CLI v1.0      ║');
        console.log('╚════════════════════════════════════╝');
        console.log('\n1. Add new password');
        console.log('2. View all passwords');
        console.log('3. Search passwords');
        console.log('4. Delete password');
        console.log('5. Generate password');
        console.log('6. View statistics');
        console.log('7. Exit');
        console.log('');
    }

    generatePasswordOnly() {
        console.log('\n=== PASSWORD GENERATOR ===');
        const length = prompt('Password length (default 16): ') || '16';
        const password = this.generatePassword(parseInt(length));
        console.log(`\n🔑 Generated password: ${password}`);
        console.log(`   Strength: ${this.checkPasswordStrength(password)}`);
        prompt('\nPress Enter to continue...');
    }

    run() {
        console.clear();
        console.log('╔════════════════════════════════════╗');
        console.log('║     PASSWORD MANAGER CLI v1.0      ║');
        console.log('╚════════════════════════════════════╝');

        if (!this.authenticate()) {
            return;
        }

        let running = true;
        while (running) {
            this.showMenu();
            const choice = prompt('Choose an option (1-7): ');

            switch (choice) {
                case '1':
                    console.clear();
                    this.addPassword();
                    prompt('\nPress Enter to continue...');
                    break;
                case '2':
                    console.clear();
                    this.viewPasswords();
                    break;
                case '3':
                    console.clear();
                    this.searchPasswords();
                    break;
                case '4':
                    console.clear();
                    this.deletePassword();
                    prompt('\nPress Enter to continue...');
                    break;
                case '5':
                    console.clear();
                    this.generatePasswordOnly();
                    break;
                case '6':
                    console.clear();
                    this.showStats();
                    break;
                case '7':
                    console.clear();
                    console.log('\n👋 Goodbye! Your passwords are safe.');
                    running = false;
                    break;
                default:
                    console.clear();
                    console.log('❌ Invalid option. Please try again.');
                    prompt('\nPress Enter to continue...');
            }
        }
    }
}

const manager = new PasswordManager();
manager.run();