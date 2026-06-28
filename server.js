const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'rummystats-dev-secret-change-in-production';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const GAMES_DIR = path.join(DATA_DIR, 'games');

app.use(express.json());
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
        sameSite: 'lax',
    },
}));

async function ensureDataDirs() {
    await fs.mkdir(GAMES_DIR, { recursive: true });
    try {
        await fs.access(USERS_FILE);
    } catch {
        await fs.writeFile(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
    }
}

async function readUsers() {
    const raw = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(raw);
}

async function writeUsers(data) {
    await fs.writeFile(USERS_FILE, JSON.stringify(data, null, 2));
}

function gameFilePath(userId) {
    return path.join(GAMES_DIR, `${userId}.json`);
}

function defaultGameData() {
    return {
        currentGame: {
            players: [],
            rounds: [],
            eliminatedPlayerIds: [],
            gameFinished: false,
            nextPlayerId: 1,
            scoreLimit: 200,
            bustGap: 25,
        },
        history: [],
    };
}

async function readGameData(userId) {
    try {
        const raw = await fs.readFile(gameFilePath(userId), 'utf8');
        return JSON.parse(raw);
    } catch {
        return defaultGameData();
    }
}

async function writeGameData(userId, data) {
    await fs.writeFile(gameFilePath(userId), JSON.stringify(data, null, 2));
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
}

function validateUsername(username) {
    if (!username || typeof username !== 'string') return 'Username is required';
    const trimmed = username.trim();
    if (trimmed.length < 3 || trimmed.length > 24) return 'Username must be 3–24 characters';
    if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) return 'Username may only contain letters, numbers, and underscores';
    return null;
}

function validatePassword(password) {
    if (!password || typeof password !== 'string') return 'Password is required';
    if (password.length < 6) return 'Password must be at least 6 characters';
    return null;
}

// ==================== AUTH API ====================

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const userError = validateUsername(username);
        if (userError) return res.status(400).json({ error: userError });
        const passError = validatePassword(password);
        if (passError) return res.status(400).json({ error: passError });

        const trimmedUsername = username.trim();
        const usersData = await readUsers();

        if (usersData.users.some(u => u.username.toLowerCase() === trimmedUsername.toLowerCase())) {
            return res.status(409).json({ error: 'Username already taken' });
        }

        const user = {
            id: crypto.randomUUID(),
            username: trimmedUsername,
            passwordHash: await bcrypt.hash(password, 10),
            createdAt: new Date().toISOString(),
        };

        usersData.users.push(user);
        await writeUsers(usersData);
        await writeGameData(user.id, defaultGameData());

        req.session.userId = user.id;
        req.session.username = user.username;

        res.json({ user: { id: user.id, username: user.username } });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const usersData = await readUsers();
        const user = usersData.users.find(
            u => u.username.toLowerCase() === username.trim().toLowerCase()
        );

        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        req.session.userId = user.id;
        req.session.username = user.username;

        res.json({ user: { id: user.id, username: user.username } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ ok: true });
    });
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({ user: { id: req.session.userId, username: req.session.username } });
});

// ==================== GAME DATA API ====================

app.get('/api/game', requireAuth, async (req, res) => {
    try {
        const data = await readGameData(req.session.userId);
        res.json(data);
    } catch (err) {
        console.error('Get game error:', err);
        res.status(500).json({ error: 'Failed to load game data' });
    }
});

app.put('/api/game', requireAuth, async (req, res) => {
    try {
        const { currentGame, history } = req.body;
        if (!currentGame || !Array.isArray(history)) {
            return res.status(400).json({ error: 'Invalid game data' });
        }
        await writeGameData(req.session.userId, { currentGame, history });
        res.json({ ok: true });
    } catch (err) {
        console.error('Save game error:', err);
        res.status(500).json({ error: 'Failed to save game data' });
    }
});

// ==================== STATIC FILES ====================

app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

ensureDataDirs().then(() => {
    app.listen(PORT, () => {
        console.log(`RummyStats server running on http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});
