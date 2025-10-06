// --- Import necessary libraries ---
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const multer = require('multer');

// --- NEW SECURITY LIBRARIES ---
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');

// --- Server Setup ---
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // In production, lock this down to your frontend's domain
    methods: ["GET", "POST"]
  }
});

const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const GUEST_DATA_FILE = path.join(__dirname, 'guestdata.json');
const FORUMS_FILE = path.join(__dirname, 'forums.json');
const TESTHUB_FILE = path.join(__dirname, 'testhub.json');
const ADMIN_MESSAGE_FILE = path.join(__dirname, 'adminmessage.json');
const BAD_WORDS_FILE = path.join(__dirname, 'words.txt');
const USER_CREATIONS_FILE = path.join(__dirname, 'user-creations.json');
const TESTHUB_LOGS_FILE = path.join(__dirname, 'testhubchatlogs.txt');

// --- (NEW) Security Configuration ---

// 1. Session Management
app.set('trust proxy', 1); // Necessary if behind a reverse proxy like Nginx
app.use(session({
    store: new FileStore({ logFn: function(){} }), // Persists sessions to a file
    secret: 'a_very_strong_and_long_random_secret_key', // CHANGE THIS to a long random string
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // In production with HTTPS, set this to true
        httpOnly: true, // Prevents client-side JS from accessing the cookie
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
}));

// 2. Rate Limiting
const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 200, // Limit each IP to 200 requests per window
	standardHeaders: true,
	legacyHeaders: false, 
});

const sensitiveActionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit sensitive actions like login/signup to 10 attempts
    message: 'Too many requests from this IP, please try again after 15 minutes',
    standardHeaders: true,
	legacyHeaders: false, 
});

app.use(apiLimiter); // Apply general limiter to all routes

// 3. XSS Sanitizer Function
function sanitize(dirty) {
    if(!dirty) return dirty;
    return sanitizeHtml(dirty, {
        allowedTags: [ 'b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li' ],
        allowedAttributes: {} // Disallow all attributes like 'href', 'onclick' etc.
    });
}


// --- Advanced Censoring System (Unchanged) ---
let badWords = new Set();
let userChatState = {};
const leetMap = { 'a': ['a', '4', '@'],'b': ['b', '8'],'c': ['c', '(', '©', '¢'],'e': ['e', '3', '€'],'g': ['g', '6', '9'],'i': ['i', '1', '!', '|'],'l': ['l', '1', '|'],'o': ['o', '0'],'s': ['s', '5', '$', '§'],'t': ['t', '7', '+'],'z': ['z', '2']};
const reverseLeetMap = {};
for (const letter in leetMap) { leetMap[letter].forEach(char => { reverseLeetMap[char] = letter; }); }
function getNormalizedString(text) { if (!text) return ''; let normalized = text.toLowerCase(); normalized = normalized.split('').map(char => reverseLeetMap[char] || char).join(''); normalized = normalized.replace(/[^\p{L}\p{N}]/gu, ''); return normalized; }
async function loadBadWords() { try { console.log('Loading bad words filter...'); if (!fsSync.existsSync(BAD_WORDS_FILE)) { console.log('[CENSOR WARNING] words.txt not found. The filter will be inactive.'); return; } const data = await fs.readFile(BAD_WORDS_FILE, 'utf8'); const words = data.split(/\r?\n/).filter(line => line.trim() !== ''); if(words.length === 0){ console.log('[CENSOR WARNING] words.txt is empty. The filter will be inactive.'); } badWords = new Set(words.map(word => getNormalizedString(word.trim()))); console.log(`[CENSOR INFO] Loaded ${badWords.size} unique words into the filter.`); } catch (error) { console.error('Could not load words.txt:', error); } }
function censor(text) { if (!text || badWords.size === 0) return { containsBadWord: false, censoredText: text }; let containsBadWord = false; let output = text.split(''); const charMap = []; text.split('').forEach((originalChar, index) => { const normalizedChar = reverseLeetMap[originalChar.toLowerCase()] || originalChar.toLowerCase(); if (/[\p{L}\p{N}]/u.test(normalizedChar)) { charMap.push({ norm: normalizedChar, index: index }); } }); if (charMap.length === 0) return { containsBadWord: false, censoredText: text }; for (let i = 0; i < charMap.length; i++) { let currentSequence = ''; for (let j = i; j < charMap.length; j++) { currentSequence += charMap[j].norm; const collapsedSequence = currentSequence.replace(/(.)\1+/gi, '$1'); if (badWords.has(collapsedSequence) || badWords.has(currentSequence)) { const originalStartIndex = charMap[i].index; const originalEndIndex = charMap[j].index; const charBefore = text[originalStartIndex - 1]; const charAfter = text[originalEndIndex + 1]; const isLeftBoundary = charBefore === undefined || !/[\p{L}\p{N}]/u.test(charBefore); const isRightBoundary = charAfter === undefined || !/[\p{L}\p{N}]/u.test(charAfter); if (isLeftBoundary && isRightBoundary) { containsBadWord = true; for (let k = originalStartIndex; k <= originalEndIndex; k++) { if (/[\p{L}\p{N}]/u.test(output[k])) { output[k] = '*'; } } } } } } return { containsBadWord, censoredText: output.join('') }; }

// --- (UPDATED) Middleware, File Upload, and other Helpers ---
app.use(express.json({limit: '50mb'}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// (NEW) Secure File Upload Configuration
const storage = multer.diskStorage({ destination: (req, file, cb) => cb(null, 'uploads/'), filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)) });
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB file size limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const mimeTypeOK = allowedTypes.test(file.mimetype);
        const extNameOK = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        if (mimeTypeOK && extNameOK) return cb(null, true);
        cb(new Error('Error: Only image files (JPEG, PNG, GIF) are allowed!'));
    }
});
const reportUpload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB limit for report attachments
});

async function readData(filePath, defaultData = null) { try { const data = await fs.readFile(filePath, 'utf8'); return data.trim() === '' ? defaultData : JSON.parse(data); } catch (error) { if (error.code === 'ENOENT') { if (defaultData) await writeData(filePath, defaultData); return defaultData; } throw error; } }
async function writeData(filePath, data) { await fs.writeFile(filePath, JSON.stringify(data, null, 2)); }
const getUsers = async () => (await readData(USERS_FILE, []));
const saveUsers = (users) => writeData(USERS_FILE, users);
const getGuestData = async () => (await readData(GUEST_DATA_FILE, { lastGuestNumber: 0, guests: {} }));
const saveGuestData = (data) => writeData(GUEST_DATA_FILE, data);
const getForumData = async () => (await readData(FORUMS_FILE, { categories: [], posts: [], spotlightPostId: null }));
const saveForumData = (data) => writeData(FORUMS_FILE, data);
const getTestHubData = async () => (await readData(TESTHUB_FILE, { jobs: [], escrow: {} }));
const saveTestHubData = (data) => writeData(TESTHUB_FILE, data);
const getAdminMessage = async () => (await readData(ADMIN_MESSAGE_FILE, { message: "", backgroundColor: "#FFFF00", textColor: "#000000", fontSize: "14", enabled: false }));
const saveAdminMessage = (data) => writeData(ADMIN_MESSAGE_FILE, data);
const getUserCreations = async () => (await readData(USER_CREATIONS_FILE, {}));
const saveUserCreations = (data) => writeData(USER_CREATIONS_FILE, data);

// --- (NEW) Authentication and Authorization Middleware ---
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.user) return next();
    res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
};

const isNotGuest = (req, res, next) => {
    if (req.session && req.session.user && !req.session.user.username.startsWith('Guest')) return next();
    res.status(403).json({ success: false, message: 'This action is for registered users only.' });
}

const isAdmin = (req, res, next) => {
    if (req.session && req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).json({ success: false, message: 'Forbidden. Administrator access required.' });
};

const isModerator = (req, res, next) => {
    if (req.session && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'moderator')) return next();
    res.status(403).json({ success: false, message: 'Forbidden. Moderator access required.' });
};

async function initializeData() { await loadBadWords(); try { await fs.access(TESTHUB_LOGS_FILE); } catch (error) { if (error.code === 'ENOENT') { await fs.writeFile(TESTHUB_LOGS_FILE, ''); console.log('Created testhubchatlogs.txt'); } } console.log('All data files checked.'); }

// --- Routes ---

// --- (UPDATED) Auth Routes ---
app.post('/signup', sensitiveActionLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required.' });
        if (username.length < 3) return res.status(400).json({ success: false, message: 'Username must be at least 3 characters.' });
        
        const result = censor(username);
        if (result.containsBadWord) return res.status(400).json({ success: false, message: 'This username is not allowed.' });
        
        const sanitizedUsername = sanitize(username);
        if (sanitizedUsername !== username) return res.status(400).json({ success: false, message: 'Username contains invalid characters.' });

        const users = await getUsers();
        if (users.find(u => u.username.toLowerCase() === sanitizedUsername.toLowerCase())) return res.status(409).json({ success: false, message: 'Username is already taken.' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ username: sanitizedUsername, password: hashedPassword, role: 'user', currencies: { diamonds: 10, sculptcoins: 0, points: 0 }, badges: [], postCount: 0, replyCount: 0 });
        
        await saveUsers(users);
        res.status(201).json({ success: true, message: 'Account created! Please log in.' });
    } catch (error) { res.status(500).json({ success: false, message: 'Server error during signup.' }); }
});

app.post('/login', sensitiveActionLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required.' });
        const users = await getUsers();
        const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        
        const { password: _, ...userSessionData } = user; // Exclude password from session data
        req.session.user = userSessionData;
        res.status(200).json({ success: true, user: userSessionData });
    } catch (error) { res.status(500).json({ success: false, message: 'Server error during login.' }); }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ success: false, message: 'Could not log out, please try again.' });
        res.clearCookie('connect.sid');
        res.status(200).json({ success: true, message: 'Logged out successfully.' });
    });
});

app.get('/check-session', (req, res) => {
    if (req.session && req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.json({ success: false, user: null });
    }
});

app.get('/guestlogin', sensitiveActionLimiter, async (req, res) => { 
    try { 
        const ip = req.ip; 
        let guestData = await getGuestData(); 
        if (!guestData.guests) guestData.guests = {}; 
        if (guestData.guests[ip]) { 
            const username = `Guest${guestData.guests[ip]}`;
            req.session.user = { username, role: 'guest' };
            return res.json({ success: true, user: req.session.user }); 
        } 
        const newGuestNumber = (guestData.lastGuestNumber || 0) + 1; 
        guestData.lastGuestNumber = newGuestNumber; 
        guestData.guests[ip] = newGuestNumber; 
        await saveGuestData(guestData); 
        
        const username = `Guest${newGuestNumber}`;
        req.session.user = { username, role: 'guest' };
        res.json({ success: true, user: req.session.user }); 
    } catch (error) { res.status(500).json({ success: false, message: "Server error during guest login." }); } 
});

app.post('/changepassword', isAuthenticated, sensitiveActionLimiter, async (req, res) => {
    const username = req.session.user.username;
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: 'All fields required.' });
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.username === username);
        if (userIndex === -1) return res.status(404).json({ success: false, message: 'User not found.' });
        const user = users[userIndex];
        if (!(await bcrypt.compare(oldPassword, user.password))) return res.status(401).json({ success: false, message: 'Incorrect old password.' });
        users[userIndex].password = await bcrypt.hash(newPassword, 10);
        await saveUsers(users);
        res.status(200).json({ success: true, message: 'Password changed successfully.' });
    } catch (error) { res.status(500).json({ success: false, message: 'Server error changing password.' }); }
});

app.post('/changeusername', isAuthenticated, isNotGuest, async (req, res) => {
    const currentUsername = req.session.user.username;
    try {
        const { newUsername, password } = req.body;
        if (!newUsername || !password) return res.status(400).json({ success: false, message: 'All fields required.' });
        const result = censor(newUsername);
        if (result.containsBadWord) return res.status(400).json({ success: false, message: 'This username is not allowed.' });
        const sanitizedNewUsername = sanitize(newUsername);
        if (sanitizedNewUsername !== newUsername) return res.status(400).json({ success: false, message: 'New username contains invalid characters.' });
        if (sanitizedNewUsername.trim().length < 3) return res.status(400).json({ success: false, message: 'New username must be at least 3 characters.' });
        if (sanitizedNewUsername.toLowerCase().startsWith('guest')) return res.status(400).json({ success: false, message: 'Username cannot start with "Guest".' });
        const users = await getUsers();
        if (users.find(u => u.username.toLowerCase() === sanitizedNewUsername.toLowerCase())) return res.status(409).json({ success: false, message: 'That username is already taken.' });
        const userIndex = users.findIndex(u => u.username === currentUsername);
        if (userIndex === -1) return res.status(404).json({ success: false, message: 'Current user not found.' });
        const user = users[userIndex];
        if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ success: false, message: 'Incorrect password.' });
        if (!user.currencies || user.currencies.diamonds < 10) return res.status(402).json({ success: false, message: 'Not enough diamonds (requires 10).' });
        const creations = await getUserCreations();
        if (creations[currentUsername]) {
            creations[sanitizedNewUsername] = creations[currentUsername];
            delete creations[currentUsername];
            await saveUserCreations(creations);
        }
        users[userIndex].username = sanitizedNewUsername;
        users[userIndex].currencies.diamonds -= 10;
        await saveUsers(users);
        req.session.user.username = sanitizedNewUsername;
        req.session.user.currencies = users[userIndex].currencies;
        const { password: _, ...updatedUser } = users[userIndex];
        res.status(200).json({ success: true, message: 'Username changed successfully!', updatedUser: updatedUser });
    } catch (error) { res.status(500).json({ success: false, message: 'Server error changing username.' }); }
});

// --- Public / General Routes ---
app.get('/spotlight', async (req, res) => { try { const forumData = await getForumData(); if (forumData.spotlightPostId && forumData.posts) { const spotlightPost = forumData.posts.find(p => p.id === forumData.spotlightPostId); if (spotlightPost) { res.json({ success: true, post: spotlightPost }); } else { res.json({ success: false, message: 'Spotlight post not found in posts list.' }); } } else { res.json({ success: true, post: null }); } } catch (error) { res.status(500).json({ success: false, message: 'Server error fetching spotlight post.' }); } });
app.get('/admin/banner', async (req, res) => { try { const messageData = await getAdminMessage(); res.json({ success: true, banner: messageData }); } catch (error) { res.status(500).json({ success: false, message: 'Could not fetch banner data.' }); } });

// --- (UPDATED) Forum Routes ---
app.get('/forums', isAuthenticated, async (req, res) => { try { const forumData = await getForumData(); const users = await getUsers(); const authors = new Set(); if (forumData && Array.isArray(forumData.posts)) { forumData.posts.forEach(post => { authors.add(post.author); if (post.replies && Array.isArray(post.replies)) { post.replies.forEach(reply => authors.add(reply.author)); } }); } const userStats = {}; authors.forEach(authorName => { const user = users.find(u => u.username === authorName); if (user) { userStats[authorName] = { postCount: user.postCount || 0, replyCount: user.replyCount || 0, badges: user.badges || [] }; } }); res.json({ forumData, userStats }); } catch (error) { res.status(500).json({ message: 'Error fetching forum data.' }); } });
app.post('/forums/post', isAuthenticated, isNotGuest, upload.single('image'), async (req, res) => {
    try {
        const username = req.session.user.username;
        const titleResult = censor(req.body.title);
        const contentResult = censor(req.body.content);
        const sanitizedTitle = sanitize(titleResult.censoredText);
        const sanitizedContent = sanitize(contentResult.censoredText);
        const newPost = { id: `post_${Date.now()}`, categoryId: parseInt(req.body.categoryId, 10), title: sanitizedTitle, content: sanitizedContent, author: username, timestamp: new Date().toISOString(), replies: [], likes: [], imageUrl: req.file ? `/uploads/${req.file.filename}` : null };
        const forumData = await getForumData();
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.username === username);
        let badgeAwardedMessage = '';
        if ((users[userIndex].postCount || 0) === 0) { users[userIndex].badges.push("1st Forum Post"); users[userIndex].currencies.points += 200; badgeAwardedMessage = "Congrats! You earned '1st Forum Post' badge and +200 Points!"; }
        users[userIndex].postCount = (users[userIndex].postCount || 0) + 1;
        forumData.posts.push(newPost);
        await saveForumData(forumData);
        await saveUsers(users);
        res.status(201).json({ success: true, message: 'Post created!', post: newPost, badgeAwardedMessage });
    } catch (error) { res.status(500).json({ success: false, message: 'Server error: ' + error.message }); }
});
app.post('/forums/reply', isAuthenticated, isNotGuest, async (req, res) => {
    try {
        const username = req.session.user.username;
        const contentResult = censor(req.body.content);
        const sanitizedContent = sanitize(contentResult.censoredText);
        const newReply = { id: `reply_${Date.now()}`, author: username, content: sanitizedContent, timestamp: new Date().toISOString() };
        const forumData = await getForumData();
        const postIndex = forumData.posts.findIndex(p => p.id === req.body.postId);
        if(postIndex === -1) return res.status(404).json({success: false, message: 'Post not found.'});
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.username === username);
        users[userIndex].replyCount = (users[userIndex].replyCount || 0) + 1;
        forumData.posts[postIndex].replies.push(newReply);
        await saveForumData(forumData);
        await saveUsers(users);
        res.status(201).json({ success: true, message: 'Reply added!', reply: newReply });
    } catch (error) { res.status(500).json({ success: false, message: 'Server error' }); }
});
app.post('/forums/like', isAuthenticated, isNotGuest, async (req, res) => { try { const username = req.session.user.username; const { postId } = req.body; const forumData = await getForumData(); const postIndex = forumData.posts.findIndex(p => p.id === postId); if (postIndex === -1) return res.status(404).json({ message: 'Post not found.' }); if (!forumData.posts[postIndex].likes) { forumData.posts[postIndex].likes = []; } if (forumData.posts[postIndex].likes.includes(username)) { return res.status(409).json({ message: 'You have already liked this post.' }); } forumData.posts[postIndex].likes.push(username); await saveForumData(forumData); res.status(200).json({ success: true, message: 'Post liked!' }); } catch (error) { res.status(500).json({ message: 'Server error liking post.' }); } });

// --- (UPDATED) Studio Routes ---
app.post('/studio/save', isAuthenticated, isNotGuest, async (req, res) => { try { const username = req.session.user.username; const { sceneData } = req.body; const creations = await getUserCreations(); creations[username] = sceneData; await saveUserCreations(creations); res.json({ success: true, message: "Scene saved successfully." }); } catch (error) { res.status(500).json({ success: false, message: "Server error while saving scene." }); } });
app.get('/studio/load', isAuthenticated, isNotGuest, async (req, res) => { try { const username = req.session.user.username; const creations = await getUserCreations(); const userScene = creations[username]; if (userScene) { res.json({ success: true, sceneData: userScene }); } else { res.json({ success: false, message: "No saved scene found for this user." }); } } catch (error) { res.status(500).json({ success: false, message: "Server error while loading scene." }); } });

// --- (UPDATED) Moderator Route ---
app.get('/moderator/chatlogs', isModerator, async (req, res) => { try { const logData = await fs.readFile(TESTHUB_LOGS_FILE, 'utf8'); const logs = logData.split('\n').filter(Boolean).map(JSON.parse); res.json({ success: true, logs }); } catch (error) { res.status(500).json({ success: false, message: 'Server error fetching chat logs.' }); } });

// --- (UPDATED) Admin Routes ---
app.post('/admin/banner', isAdmin, async (req, res) => { try { const { message, backgroundColor, textColor, fontSize, enabled } = req.body; const sanitizedMessage = sanitizeHtml(message); await saveAdminMessage({ message: sanitizedMessage, backgroundColor, textColor, fontSize, enabled }); res.json({ success: true, message: 'Banner updated successfully.' }); } catch (error) { res.status(500).json({ success: false, message: 'Server error updating banner.' }); } });
app.post('/admin/award-badge', isAdmin, async (req, res) => { try { const { targetUsername } = req.body; const users = await getUsers(); const targetUserIndex = users.findIndex(u => u.username === targetUsername); if (targetUserIndex === -1) { return res.status(404).json({ success: false, message: 'Target user not found.' }); } if (users[targetUserIndex].badges.includes("Forum Hall of Fame")) { return res.status(409).json({ success: false, message: 'User already has this badge.' }); } users[targetUserIndex].badges.push("Forum Hall of Fame"); users[targetUserIndex].currencies.sculptcoins += 5000; users[targetUserIndex].currencies.points += 15594; await saveUsers(users); res.status(200).json({ success: true, message: `Successfully awarded "Forum Hall of Fame" badge to ${targetUsername}.` }); } catch (error) { res.status(500).json({ success: false, message: 'Server error during badge award.' }); } });
app.post('/admin/award-spotlight', isAdmin, async (req, res) => { try { const { postId } = req.body; const forumData = await getForumData(); const users = await getUsers(); const post = forumData.posts.find(p => p.id === postId); if (!post) { return res.status(404).json({ success: false, message: 'The selected post could not be found.' }); } const targetUserIndex = users.findIndex(u => u.username === post.author); if (targetUserIndex === -1) { return res.status(404).json({ success: false, message: 'The post author could not be found.' }); } users[targetUserIndex].currencies.points += 8000; if (!users[targetUserIndex].badges.includes("Forum Spotlight Badge")) { users[targetUserIndex].badges.push("Forum Spotlight Badge"); } forumData.spotlightPostId = postId; await saveUsers(users); await saveForumData(forumData); res.status(200).json({ success: true, message: `The post by ${post.author} has been featured in the Forum Spotlight!` }); } catch (error) { res.status(500).json({ success: false, message: 'A server error occurred while awarding the spotlight.' }); } });
app.post('/admin/delete-spotlight', isAdmin, async (req, res) => { try { const forumData = await getForumData(); forumData.spotlightPostId = null; await saveForumData(forumData); res.status(200).json({ success: true, message: 'Forum Spotlight has been cleared.' }); } catch (error) { res.status(500).json({ success: false, message: 'A server error occurred while clearing the spotlight.' }); } });
app.post('/admin/delete-post', isAdmin, async (req, res) => { try { const { postId } = req.body; const forumData = await getForumData(); const initialLength = forumData.posts.length; forumData.posts = forumData.posts.filter(p => p.id !== postId); if (forumData.posts.length === initialLength) { return res.status(404).json({ success: false, message: 'Post not found.' }); } if(forumData.spotlightPostId === postId) { forumData.spotlightPostId = null; } await saveForumData(forumData); res.json({ success: true, message: 'Post and all replies have been deleted.' }); } catch (error) { res.status(500).json({ success: false, message: 'Server error deleting post.' }); } });
app.post('/admin/delete-reply', isAdmin, async (req, res) => { try { const { postId, replyId } = req.body; const forumData = await getForumData(); const postIndex = forumData.posts.findIndex(p => p.id === postId); if (postIndex === -1) return res.status(404).json({ message: 'Post not found.' }); const initialLength = forumData.posts[postIndex].replies.length; forumData.posts[postIndex].replies = forumData.posts[postIndex].replies.filter(r => r.id !== replyId); if (forumData.posts[postIndex].replies.length === initialLength) { return res.status(404).json({ success: false, message: 'Reply not found.' }); } await saveForumData(forumData); res.json({ success: true, message: 'Reply has been deleted.' }); } catch (error) { res.status(500).json({ success: false, message: 'Server error deleting reply.' }); } });
app.post('/admin/relocate-post', isAdmin, async (req, res) => { try { const { postId, newCategoryId } = req.body; const forumData = await getForumData(); const postIndex = forumData.posts.findIndex(p => p.id === postId); if (postIndex === -1) return res.status(404).json({ message: 'Post not found.' }); const categoryExists = forumData.categories.some(c => c.id == newCategoryId); if (!categoryExists) return res.status(404).json({ message: 'Target category not found.' }); forumData.posts[postIndex].categoryId = parseInt(newCategoryId, 10); await saveForumData(forumData); res.json({ success: true, message: 'Post has been relocated.' }); } catch (error) { res.status(500).json({ success: false, message: 'Server error relocating post.' }); } });

// --- (UPDATED) TestHub Routes ---
app.post('/testhub/job', isAuthenticated, isNotGuest, async (req, res) => { try { const username = req.session.user.username; const { title, description, gameLink, requirements, amount, paymentMethod } = req.body; const users = await getUsers(); const userIndex = users.findIndex(u => u.username === username); if (userIndex === -1) return res.status(404).json({ message: "User not found." }); const paymentAmount = parseInt(amount, 10); if (isNaN(paymentAmount) || paymentAmount <= 0) return res.status(400).json({ message: "Invalid payment amount." }); const currencyKey = paymentMethod === 'SculptCoins' ? 'sculptcoins' : 'points'; if (users[userIndex].currencies[currencyKey] < paymentAmount) { return res.status(402).json({ message: `Insufficient ${paymentMethod}.` }); } users[userIndex].currencies[currencyKey] -= paymentAmount; const testHubData = await getTestHubData(); const newJob = { id: `job_${Date.now()}`, posterUsername: username, title: sanitize(title), description: sanitize(description), gameLink: sanitize(gameLink), requirements: sanitize(requirements), paymentAmount, paymentMethod, status: 'open', testerUsername: null, applicants: [], chat: [], reports: [] }; testHubData.jobs.push(newJob); testHubData.escrow[newJob.id] = { amount: paymentAmount, currency: paymentMethod }; await saveUsers(users); await saveTestHubData(testHubData); res.status(201).json({ success: true, message: "Job posted successfully! Payment is now in escrow." }); } catch (error) { res.status(500).json({ message: "Server error while posting job." }); } });
app.get('/testhub/jobs', isAuthenticated, async (req, res) => { try { const testHubData = await getTestHubData(); const openJobs = testHubData.jobs.filter(job => job.status === 'open'); res.json({ success: true, jobs: openJobs }); } catch (error) { res.status(500).json({ message: "Server error fetching jobs." }); } });
app.get('/testhub/messages', isAuthenticated, async (req, res) => { try { const username = req.session.user.username; const testHubData = await getTestHubData(); const relevantJobs = testHubData.jobs.filter(job => job.posterUsername === username || job.testerUsername === username || job.applicants.some(app => app.username === username)); res.json({ success: true, jobs: relevantJobs }); } catch(error) { res.status(500).json({ message: 'Server error fetching messages.' }); } });
app.post('/testhub/message', isAuthenticated, isNotGuest, async (req, res) => { try { const username = req.session.user.username; const { text, jobId } = req.body; if (!userChatState[username]) userChatState[username] = { history: "" }; const combined = userChatState[username].history + " " + text; const result = censor(combined); let finalCensoredText = censor(text).censoredText; if (result.containsBadWord) { userChatState[username].history = ""; } else { const maxHistory = 30; userChatState[username].history = combined.slice(-maxHistory); } const sanitizedText = sanitize(finalCensoredText); const testHubData = await getTestHubData(); const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId); if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' }); const timestamp = new Date().toISOString(); testHubData.jobs[jobIndex].chat.push({ sender: username, text: sanitizedText, timestamp: timestamp }); const logEntry = { jobId, timestamp, sender: username, text: sanitizedText }; await fs.appendFile(TESTHUB_LOGS_FILE, JSON.stringify(logEntry) + '\n'); await saveTestHubData(testHubData); res.json({ success: true, message: "Message sent." }); } catch (error) { res.status(500).json({ success: false, message: "Server error sending message." }); } });
app.post('/testhub/apply', isAuthenticated, isNotGuest, async (req, res) => { try { const username = req.session.user.username; const { jobId } = req.body; const testHubData = await getTestHubData(); const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId); if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' }); const job = testHubData.jobs[jobIndex]; if (job.posterUsername === username) return res.status(400).json({ message: "You cannot apply to your own job." }); if (job.applicants.some(app => app.username === username)) return res.status(409).json({ message: "You have already applied." }); const firstMessage = `Hello! I'm interested in testing your game.`; job.applicants.push({ username }); job.chat.push({ sender: username, text: firstMessage, timestamp: new Date().toISOString() }); await saveTestHubData(testHubData); res.json({ success: true, message: "Application sent!" }); } catch (error) { res.status(500).json({ message: "Server error during application." }); } });
app.post('/testhub/accept', isAuthenticated, isNotGuest, async (req, res) => { try { const posterUsername = req.session.user.username; const { applicantUsername, jobId } = req.body; const testHubData = await getTestHubData(); const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId); if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' }); const job = testHubData.jobs[jobIndex]; if (job.posterUsername !== posterUsername) return res.status(403).json({ message: "You are not the owner of this job." }); if (job.status !== 'open') return res.status(400).json({ message: "This job is not open for applications." }); job.status = 'in_progress'; job.testerUsername = applicantUsername; job.chat.push({ sender: 'System', text: `${applicantUsername} has been accepted as the tester.`, timestamp: new Date().toISOString() }); await saveTestHubData(testHubData); res.json({ success: true, message: `${applicantUsername} accepted!` }); } catch (error) { res.status(500).json({ message: "Server error while accepting applicant." }); } });
app.post('/testhub/submit-report', isAuthenticated, isNotGuest, reportUpload.array('attachments'), async (req, res) => { try { const username = req.session.user.username; const { jobId, title, findings } = req.body; const testHubData = await getTestHubData(); const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId); if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' }); const job = testHubData.jobs[jobIndex]; if (job.testerUsername !== username) return res.status(403).json({ message: "You are not the tester for this job." }); const newReport = { id: `report_${Date.now()}`, title: sanitize(title), findings: sanitize(findings), attachments: req.files ? req.files.map(file => `/uploads/${file.filename}`) : [], timestamp: new Date().toISOString() }; job.reports.push(newReport); job.chat.push({ sender: 'System', text: `${username} submitted a new test report: "${sanitize(title)}"`, timestamp: new Date().toISOString() }); await saveTestHubData(testHubData); res.json({ success: true, message: "Test report submitted!" }); } catch (error) { res.status(500).json({ message: "Server error submitting report." }); } });
app.post('/testhub/complete-job', isAuthenticated, isNotGuest, async (req, res) => { try { const posterUsername = req.session.user.username; const { jobId } = req.body; const testHubData = await getTestHubData(); const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId); if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' }); const job = testHubData.jobs[jobIndex]; if (job.posterUsername !== posterUsername) return res.status(403).json({ message: "You are not the owner of this job." }); if (job.status !== 'in_progress') return res.status(400).json({ message: "Job is not in progress." }); const escrowedPayment = testHubData.escrow[jobId]; if (!escrowedPayment) return res.status(500).json({ message: "Critical error: Escrow data not found." }); const users = await getUsers(); const testerIndex = users.findIndex(u => u.username === job.testerUsername); if (testerIndex === -1) return res.status(404).json({ message: "Tester account not found." }); const currencyKey = escrowedPayment.currency === 'SculptCoins' ? 'sculptcoins' : 'points'; users[testerIndex].currencies[currencyKey] = (users[testerIndex].currencies[currencyKey] || 0) + escrowedPayment.amount; job.status = 'completed'; delete testHubData.escrow[jobId]; await saveUsers(users); await saveTestHubData(testHubData); res.json({ success: true, message: `Payment of ${escrowedPayment.amount} ${escrowedPayment.currency} has been released to ${job.testerUsername}.` }); } catch (error) { res.status(500).json({ message: "Server error while completing job." }); } });

// --- Socket.IO for Online Count (Unchanged) ---
let onlineUsers = 0;
io.on('connection', (socket) => { onlineUsers++; io.emit('userCount', onlineUsers); socket.on('disconnect', () => { onlineUsers--; io.emit('userCount', onlineUsers); }); });

// --- Start Server ---
server.listen(PORT, async () => {
    await initializeData();
    console.log(`Server is running at http://localhost:${PORT}`);
});