const express = require('express')
const { port } = require('./config.js') // (1) port configuration
const fs = require('fs') // (2) file system access for users.json
const bcrypt = require('bcrypt'); // (3) bcrypt for password hashing

const app = express() // (4) initialize express
app.use(express.urlencoded({ extended: false })); // (5) body parser for form submissions

// (6) Load users from JSON file (returns empty array if missing)
function loadUsers(file) {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// (7) Save users back to JSON file (synchronous for simplicity)
function saveUsers(file, users) {
    fs.writeFileSync(file, JSON.stringify(users, null, 2), 'utf8');
}

// (8) Compare plaintext password with bcrypt hash
async function checkPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

app.set('view engine', 'ejs') // (9) use EJS views from views/ directory

// (10) ADMIN PASSWORD placeholder — set this to your chosen control-panel password.
// For demo: change 'CHANGE_ME' to the admin password you will use.
const ADMIN_PASSWORD = 'rikuonadmin' // <-- change this before deploying

// (11) Root redirects (example)
app.get('/', (req, res) => {
    res.redirect('/login')
})

// (12) Render the login page. The login view now contains links to register and control panel.
app.get('/login', (req, res) => {
    res.render('login', { virhe: '' })
})

// (13) Process login attempts.
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers('users.json');
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }
    const match = await checkPassword(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid username or password' });
    res.json({ message: 'Login successful!' });
})

// (14) Show registration form
app.get('/register', (req, res) => {
    res.render('register', { virhe: '' })
})

// (15) Process registration: creates a new user with a bcrypt-hashed password
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('username and password required');
    const users = loadUsers('users.json');
    if (users.find(u => u.username === username)) return res.status(400).send('username already exists');
    const hash = await bcrypt.hash(password, 12);
    users.push({ username, password: hash });
    saveUsers('users.json', users);
    res.redirect('/login');
})

// (16) Control panel: first show password form to access management features
app.get('/control', (req, res) => {
    res.render('control_login', { virhe: '' })
})

// (17) Verify admin password and show control panel with user list
app.post('/control', (req, res) => {
    const { adminPassword } = req.body;
    if (adminPassword !== ADMIN_PASSWORD) {
        return res.render('control_login', { virhe: 'Incorrect control-panel password' })
    }
    const users = loadUsers('users.json');
    res.render('control_panel', { users })
})

// (18) Edit user form — requires adminPassword as hidden field in the form (simple re-auth)
app.get('/control/edit/:username', (req, res) => {
    const username = decodeURIComponent(req.params.username);
    const users = loadUsers('users.json');
    const user = users.find(u => u.username === username);
    if (!user) return res.status(404).send('User not found');
    res.render('edit_user', { user, virhe: '' })
})

// (19) Handle edits — requires adminPassword in body (demo-only auth)
app.post('/control/edit/:username', async (req, res) => {
    const oldUsername = decodeURIComponent(req.params.username);
    const { username, password, adminPassword } = req.body;
    if (adminPassword !== ADMIN_PASSWORD) return res.status(401).send('Unauthorized');
    const users = loadUsers('users.json');
    const idx = users.findIndex(u => u.username === oldUsername);
    if (idx === -1) return res.status(404).send('User not found');
    // Update username
    users[idx].username = username || users[idx].username;
    // Update password if provided (hash it)
    if (password && password.length > 0) {
        users[idx].password = await bcrypt.hash(password, 12);
    }
    saveUsers('users.json', users);
    res.redirect('/control')
})

// (20) Delete user — requires adminPassword in body
app.post('/control/delete/:username', (req, res) => {
    const username = decodeURIComponent(req.params.username);
    const { adminPassword } = req.body;
    if (adminPassword !== ADMIN_PASSWORD) return res.status(401).send('Unauthorized');
    let users = loadUsers('users.json');
    users = users.filter(u => u.username !== username);
    saveUsers('users.json', users);
    res.redirect('/control')
})

// (21) Start server
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})