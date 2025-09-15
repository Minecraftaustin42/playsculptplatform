// --- Import necessary libraries ---
const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const fsSync = require('fs'); // For synchronous file check
const path = require('path');
const multer = require('multer');

// --- Server Setup ---
const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const GUEST_DATA_FILE = path.join(__dirname, 'guestdata.json');
const FORUMS_FILE = path.join(__dirname, 'forums.json');
const TESTHUB_FILE = path.join(__dirname, 'testhub.json');
const ADMIN_MESSAGE_FILE = path.join(__dirname, 'adminmessage.json');
const BAD_WORDS_FILE = path.join(__dirname, 'words.txt');

let badWords = new Set();

// --- Middleware ---
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.set('trust proxy', 1);

// --- File Upload Setup (Multer) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname))
    }
});
const upload = multer({ storage: storage });

// --- Helper Functions ---
async function readData(filePath, defaultData = null) {
    try {
        const data = await fs.readFile(filePath, 'utf8');
        return data.trim() === '' ? defaultData : JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') { 
            if (defaultData) await writeData(filePath, defaultData);
            return defaultData; 
        }
        throw error;
    }
}

async function writeData(filePath, data) {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
}

async function loadBadWords() {
    try {
        console.log('Loading bad words filter...');
        if (!fsSync.existsSync(BAD_WORDS_FILE)) {
            console.log('words.txt not found, skipping filter.');
            return;
        }
        const data = await fs.readFile(BAD_WORDS_FILE, 'utf8');
        const words = data.split(/\r?\n/).filter(line => line.trim() !== '').map(word => word.trim().toLowerCase());
        badWords = new Set(words);
        console.log(`Loaded ${badWords.size} words into the filter.`);
    } catch (error) {
        console.error('Could not load words.txt:', error);
    }
}

function censorText(text) {
    if (!text || badWords.size === 0) return text;
    // Create a regex to find any of the bad words, case-insensitively
    const regex = new RegExp([...badWords].join('|'), 'gi');
    return text.replace(regex, match => '*'.repeat(match.length));
}

const getUsers = async () => (await readData(USERS_FILE, []));
const saveUsers = (users) => writeData(USERS_FILE, users);
const getGuestData = async () => (await readData(GUEST_DATA_FILE, { lastGuestNumber: 0, guests: {} }));
const saveGuestData = (data) => writeData(GUEST_DATA_FILE, data);
const getForumData = async () => (await readData(FORUMS_FILE, { categories: [], posts: [], spotlightPostId: null }));
const saveForumData = (data) => writeData(FORUMS_FILE, data);
const getTestHubData = async () => {
    let data = await readData(TESTHUB_FILE, { jobs: [], escrow: {} });
    if (!Array.isArray(data.jobs)) data.jobs = [];
    if (typeof data.escrow !== 'object' || data.escrow === null) data.escrow = {};
    return data;
};
const saveTestHubData = (data) => writeData(TESTHUB_FILE, data);
const getAdminMessage = async () => (await readData(ADMIN_MESSAGE_FILE, { message: "", backgroundColor: "#FFFF00", textColor: "#000000", fontSize: "14", enabled: false }));
const saveAdminMessage = (data) => writeData(ADMIN_MESSAGE_FILE, data);


// --- Initialization Function ---
async function initializeData() {
    await loadBadWords(); // Load the word filter
    console.log('Checking data files...');
    // Initialize Forums
    const forumData = await getForumData();
    let forumNeedsSave = false;
    const defaultCategories = [
        { id: 1, name: "Help and Feedback" },
        { id: 2, name: "Game Development Feedback" },
        { id: 3, name: "Off Topic" },
        { id: 4, name: "Updates" },
        { id: 5, name: "Bug Reports" },
        { id: 6, name: "Feature Requests" },
        { id: 7, name: "Tutorials" },
        { id: 8, name: "Count to 16,044", special: 'counting_game' },
        { id: 9, name: "Introduce Yourself", label: "Do not share any personal details...", special: 'no_replies_likeable' },
        { id: 10, name: "Playsculpt Wishlists", label: "Share your wishlist for your dream items..." },
        { id: 11, name: "Game Showcase", label: "Visually share your game that you've been sculpting!", special: 'image_upload' },
        { id: 12, name: "Would You Rather...?", label: "Community-made would you rather polls!"},
        { id: 13, name: "Test My Game", label: "Ask/recruit players to test your game!", special: 'testhub_link'}
    ];
    if (!forumData.categories || forumData.categories.length !== defaultCategories.length) {
        forumData.categories = defaultCategories;
        forumNeedsSave = true;
    }
    if (!Array.isArray(forumData.posts)) { forumData.posts = []; forumNeedsSave = true; }
    if (!forumData.hasOwnProperty('spotlightPostId')) { forumData.spotlightPostId = null; forumNeedsSave = true; }
    if (forumNeedsSave) { await saveForumData(forumData); console.log('Forum data initialized.'); }
    
    // Initialize Admin Message File
    await getAdminMessage(); // This will create the file with defaults if it doesn't exist
    console.log('All data files checked.');
}

// --- Authentication and User Routes ---
app.get('/guestlogin', async (req, res) => {
    try {
        const ip = req.ip;
        let guestData = await getGuestData();
        if (!guestData.guests) guestData.guests = {};
        if (guestData.guests[ip]) {
            return res.json({ success: true, username: `Guest${guestData.guests[ip]}` });
        }
        const newGuestNumber = (guestData.lastGuestNumber || 0) + 1;
        guestData.lastGuestNumber = newGuestNumber;
        guestData.guests[ip] = newGuestNumber;
        await saveGuestData(guestData);
        res.json({ success: true, username: `Guest${newGuestNumber}` });
    } catch (error) {
        console.error("Guest login error:", error);
        res.status(500).json({ success: false, message: "Server error during guest login." });
    }
});

app.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required.' });
        const users = await getUsers();
        if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
            return res.status(409).json({ success: false, message: 'Username is already taken.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({
            username,
            password: hashedPassword,
            currencies: { diamonds: 10, sculptcoins: 0, points: 0 },
            badges: [],
            postCount: 0,
            replyCount: 0
        });
        await saveUsers(users);
        res.status(201).json({ success: true, message: 'Account created! Please log in.' });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ success: false, message: 'Server error during signup.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required.' });
        const users = await getUsers();
        const user = users.find(u => u.username === username);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }
        res.status(200).json({ success: true, username: user.username, currencies: user.currencies });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

app.post('/changepassword', async (req, res) => {
    try {
        const { username, oldPassword, newPassword } = req.body;
        if (!username || !oldPassword || !newPassword) return res.status(400).json({ success: false, message: 'All fields required.' });
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.username === username);
        if (userIndex === -1) return res.status(404).json({ success: false, message: 'User not found.' });
        const user = users[userIndex];
        if (!(await bcrypt.compare(oldPassword, user.password))) {
            return res.status(401).json({ success: false, message: 'Incorrect old password.' });
        }
        users[userIndex].password = await bcrypt.hash(newPassword, 10);
        await saveUsers(users);
        res.status(200).json({ success: true, message: 'Password changed successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error changing password.' });
    }
});

app.post('/changeusername', async (req, res) => {
    try {
        const { currentUsername, newUsername, password } = req.body;
        if (!currentUsername || !newUsername || !password) return res.status(400).json({ success: false, message: 'All fields required.' });
        if (newUsername.trim().length < 3) return res.status(400).json({ success: false, message: 'New username must be at least 3 characters.' });
        if (newUsername.toLowerCase().startsWith('guest')) return res.status(400).json({ success: false, message: 'Username cannot start with "Guest".' });
        
        const users = await getUsers();
        if (users.find(u => u.username.toLowerCase() === newUsername.toLowerCase())) {
            return res.status(409).json({ success: false, message: 'That username is already taken.' });
        }
        
        const userIndex = users.findIndex(u => u.username === currentUsername);
        if (userIndex === -1) return res.status(404).json({ success: false, message: 'Current user not found.' });
        
        const user = users[userIndex];
        if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ success: false, message: 'Incorrect password.' });
        if (!user.currencies || user.currencies.diamonds < 10) return res.status(402).json({ success: false, message: 'Not enough diamonds (requires 10).' });
        
        users[userIndex].username = newUsername;
        users[userIndex].currencies.diamonds -= 10;
        await saveUsers(users);
        
        res.status(200).json({ success: true, message: 'Username changed successfully!', updatedUser: users[userIndex] });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error changing username.' });
    }
});

// --- Forum API Routes ---
app.get('/spotlight', async (req, res) => {
    try {
        const forumData = await getForumData();
        if (forumData.spotlightPostId && forumData.posts) {
            const spotlightPost = forumData.posts.find(p => p.id === forumData.spotlightPostId);
            if (spotlightPost) {
                res.json({ success: true, post: spotlightPost });
            } else {
                res.json({ success: false, message: 'Spotlight post not found in posts list.' });
            }
        } else {
            res.json({ success: true, post: null });
        }
    } catch (error) {
        console.error('Error fetching spotlight post:', error);
        res.status(500).json({ success: false, message: 'Server error fetching spotlight post.' });
    }
});

app.get('/forums', async (req, res) => {
    try {
        const forumData = await getForumData();
        const users = await getUsers();
        const authors = new Set();
        if (forumData && Array.isArray(forumData.posts)) {
            forumData.posts.forEach(post => {
                authors.add(post.author);
                if (post.replies && Array.isArray(post.replies)) {
                    post.replies.forEach(reply => authors.add(reply.author));
                }
            });
        }
        const userStats = {};
        authors.forEach(authorName => {
            const user = users.find(u => u.username === authorName);
            if (user) {
                userStats[authorName] = {
                    postCount: user.postCount || 0,
                    replyCount: user.replyCount || 0,
                    badges: user.badges || []
                };
            }
        });
        res.json({ forumData, userStats });
    } catch (error) {
        console.error('Error fetching forum data:', error);
        res.status(500).json({ message: 'Error fetching forum data.' });
    }
});

app.post('/forums/post', upload.single('image'), async (req, res) => {
    try {
        const { username, title, content, categoryId } = req.body;
        if (!username || username.startsWith('Guest')) return res.status(403).json({ message: 'Only registered users can post.' });
        if (!title || !content || !categoryId) return res.status(400).json({ message: 'All fields are required.' });
        if (title.length > 75 || content.length > 2000) return res.status(400).json({ message: 'Post exceeds character limits.' });

        const forumData = await getForumData();
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.username === username);
        if (userIndex === -1) return res.status(404).json({ message: 'User not found.' });
        
        let badgeAwardedMessage = '';
        if ((users[userIndex].postCount || 0) === 0 && !users[userIndex].badges.includes("1st Forum Post")) {
            users[userIndex].badges.push("1st Forum Post");
            users[userIndex].currencies.points += 200;
            badgeAwardedMessage = "Congratulations! You've earned the '1st Forum Post' badge and +200 Points!";
        }
        users[userIndex].postCount = (users[userIndex].postCount || 0) + 1;

        const newPost = {
            id: `post_${Date.now()}`,
            categoryId: parseInt(categoryId, 10),
            title: censorText(title),
            content: censorText(content),
            author: username,
            timestamp: new Date().toISOString(),
            replies: [],
            likes: [],
            imageUrl: req.file ? `/uploads/${req.file.filename}` : null
        };
        forumData.posts.push(newPost);
        await saveForumData(forumData);
        await saveUsers(users);
        res.status(201).json({ success: true, message: 'Post created!', post: newPost, badgeAwardedMessage });
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ message: 'Server error creating post.' });
    }
});

app.post('/forums/reply', async (req, res) => {
    try {
        const { username, content, postId } = req.body;
        if (!username || username.startsWith('Guest')) return res.status(403).json({ message: 'Only registered users can reply.' });
        if (!content || !postId) return res.status(400).json({ message: 'Content and post ID are required.' });
        if (content.length > 1000) return res.status(400).json({ message: 'Reply exceeds character limits.' });
        
        const forumData = await getForumData();
        const postIndex = forumData.posts.findIndex(p => p.id === postId);
        if (postIndex === -1) return res.status(404).json({ message: 'Post not found.' });
        
        const category = forumData.categories.find(c => c.id === forumData.posts[postIndex].categoryId);
        if (category && category.special === 'counting_game') {
            const lastReply = forumData.posts[postIndex].replies.slice(-1)[0];
            const nextNumber = lastReply ? parseInt(lastReply.content, 10) + 1 : 1;
            if (parseInt(content, 10) !== nextNumber || !/^\d+$/.test(content)) {
                return res.status(400).json({ message: `Invalid number. The next number must be ${nextNumber}.` });
            }
        }
        
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.username === username);
        if (userIndex === -1) return res.status(404).json({ message: 'User not found.' });
        users[userIndex].replyCount = (users[userIndex].replyCount || 0) + 1;
        const newReply = { 
            id: `reply_${Date.now()}`, 
            author: username, 
            content: censorText(content), 
            timestamp: new Date().toISOString() 
        };
        forumData.posts[postIndex].replies.push(newReply);
        await saveForumData(forumData);
        await saveUsers(users);
        res.status(201).json({ success: true, message: 'Reply added!', reply: newReply });
    } catch (error) {
        console.error('Error creating reply:', error);
        res.status(500).json({ message: 'Server error creating reply.' });
    }
});

app.post('/forums/like', async (req, res) => {
    try {
        const { username, postId } = req.body;
        if (!username || username.startsWith('Guest')) {
            return res.status(403).json({ message: 'Only registered users can like posts.' });
        }
        const forumData = await getForumData();
        const postIndex = forumData.posts.findIndex(p => p.id === postId);
        if (postIndex === -1) return res.status(404).json({ message: 'Post not found.' });
        
        if (!forumData.posts[postIndex].likes) {
            forumData.posts[postIndex].likes = [];
        }
        if (forumData.posts[postIndex].likes.includes(username)) {
            return res.status(409).json({ message: 'You have already liked this post.' });
        }
        forumData.posts[postIndex].likes.push(username);
        await saveForumData(forumData);
        res.status(200).json({ success: true, message: 'Post liked!' });
    } catch (error) {
        console.error('Error liking post:', error);
        res.status(500).json({ message: 'Server error liking post.' });
    }
});

// --- Admin Banner Routes ---
app.get('/admin/banner', async (req, res) => {
    try {
        const messageData = await getAdminMessage();
        res.json({ success: true, banner: messageData });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Could not fetch banner data.' });
    }
});

app.post('/admin/banner', async (req, res) => {
    try {
        const { adminUsername, message, backgroundColor, textColor, fontSize, enabled } = req.body;
        if (adminUsername !== "Admin") {
            return res.status(403).json({ success: false, message: "Unauthorized." });
        }
        await saveAdminMessage({ message, backgroundColor, textColor, fontSize, enabled });
        res.json({ success: true, message: 'Banner updated successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error updating banner.' });
    }
});

// --- Admin Forum Routes ---
app.post('/admin/award-badge', async (req, res) => {
    try {
        const { adminUsername, targetUsername } = req.body;
        if (adminUsername !== "Admin") {
            return res.status(403).json({ success: false, message: 'You are not authorized to perform this action.' });
        }
        const users = await getUsers();
        const targetUserIndex = users.findIndex(u => u.username === targetUsername);
        if (targetUserIndex === -1) {
            return res.status(404).json({ success: false, message: 'Target user not found.' });
        }
        if (users[targetUserIndex].badges.includes("Forum Hall of Fame")) {
            return res.status(409).json({ success: false, message: 'User already has this badge.' });
        }
        users[targetUserIndex].badges.push("Forum Hall of Fame");
        users[targetUserIndex].currencies.sculptcoins += 5000;
        users[targetUserIndex].currencies.points += 15594;
        await saveUsers(users);
        res.status(200).json({ success: true, message: `Successfully awarded "Forum Hall of Fame" badge to ${targetUsername}.` });
    } catch (error) {
        console.error('Admin award badge error:', error);
        res.status(500).json({ success: false, message: 'Server error during badge award.' });
    }
});

app.post('/admin/award-spotlight', async (req, res) => {
    try {
        const { adminUsername, postId } = req.body;
        if (adminUsername !== "Admin") {
            return res.status(403).json({ success: false, message: 'Unauthorized action.' });
        }
        const forumData = await getForumData();
        const users = await getUsers();
        const post = forumData.posts.find(p => p.id === postId);
        if (!post) {
            return res.status(404).json({ success: false, message: 'The selected post could not be found.' });
        }
        const targetUserIndex = users.findIndex(u => u.username === post.author);
        if (targetUserIndex === -1) {
            return res.status(404).json({ success: false, message: 'The post author could not be found.' });
        }
        users[targetUserIndex].currencies.points += 8000;
        if (!users[targetUserIndex].badges.includes("Forum Spotlight Badge")) {
            users[targetUserIndex].badges.push("Forum Spotlight Badge");
        }
        forumData.spotlightPostId = postId;
        await saveUsers(users);
        await saveForumData(forumData);
        res.status(200).json({ success: true, message: `The post by ${post.author} has been featured in the Forum Spotlight!` });
    } catch (error) {
        console.error('Admin award spotlight error:', error);
        res.status(500).json({ success: false, message: 'A server error occurred while awarding the spotlight.' });
    }
});

app.post('/admin/delete-spotlight', async (req, res) => {
    try {
        const { adminUsername } = req.body;
        if (adminUsername !== "Admin") {
            return res.status(403).json({ success: false, message: 'Unauthorized action.' });
        }
        const forumData = await getForumData();
        forumData.spotlightPostId = null;
        await saveForumData(forumData);
        res.status(200).json({ success: true, message: 'Forum Spotlight has been cleared.' });
    } catch (error) {
        console.error('Admin delete spotlight error:', error);
        res.status(500).json({ success: false, message: 'A server error occurred while clearing the spotlight.' });
    }
});

app.post('/admin/delete-post', async (req, res) => {
    try {
        const { adminUsername, postId } = req.body;
        if (adminUsername !== "Admin") return res.status(403).json({ message: 'Unauthorized.' });
        
        const forumData = await getForumData();
        const initialLength = forumData.posts.length;
        forumData.posts = forumData.posts.filter(p => p.id !== postId);
        
        if (forumData.posts.length === initialLength) {
            return res.status(404).json({ success: false, message: 'Post not found.' });
        }
        
        if(forumData.spotlightPostId === postId) {
            forumData.spotlightPostId = null;
        }
        await saveForumData(forumData);
        res.json({ success: true, message: 'Post and all replies have been deleted.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error deleting post.' });
    }
});

app.post('/admin/delete-reply', async (req, res) => {
    try {
        const { adminUsername, postId, replyId } = req.body;
        if (adminUsername !== "Admin") return res.status(403).json({ message: 'Unauthorized.' });
        const forumData = await getForumData();
        const postIndex = forumData.posts.findIndex(p => p.id === postId);
        if (postIndex === -1) return res.status(404).json({ message: 'Post not found.' });
        
        const initialLength = forumData.posts[postIndex].replies.length;
        forumData.posts[postIndex].replies = forumData.posts[postIndex].replies.filter(r => r.id !== replyId);
        if (forumData.posts[postIndex].replies.length === initialLength) {
            return res.status(404).json({ success: false, message: 'Reply not found.' });
        }
        await saveForumData(forumData);
        res.json({ success: true, message: 'Reply has been deleted.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error deleting reply.' });
    }
});

app.post('/admin/relocate-post', async (req, res) => {
    try {
        const { adminUsername, postId, newCategoryId } = req.body;
        if (adminUsername !== "Admin") return res.status(403).json({ message: 'Unauthorized.' });
        const forumData = await getForumData();
        const postIndex = forumData.posts.findIndex(p => p.id === postId);
        if (postIndex === -1) return res.status(404).json({ message: 'Post not found.' });
        const categoryExists = forumData.categories.some(c => c.id == newCategoryId);
        if (!categoryExists) return res.status(404).json({ message: 'Target category not found.' });
        forumData.posts[postIndex].categoryId = parseInt(newCategoryId, 10);
        await saveForumData(forumData);
        res.json({ success: true, message: 'Post has been relocated.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error relocating post.' });
    }
});

// --- SculptTest Hub API Routes ---
app.post('/testhub/job', async (req, res) => {
    try {
        const { username, title, description, gameLink, requirements, amount, paymentMethod } = req.body;
        if (!username || username.startsWith('Guest')) return res.status(403).json({ message: "You must be logged in to post a job." });
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.username === username);
        if (userIndex === -1) return res.status(404).json({ message: "User not found." });
        const paymentAmount = parseInt(amount, 10);
        if (isNaN(paymentAmount) || paymentAmount <= 0) return res.status(400).json({ message: "Invalid payment amount." });
        const currencyKey = paymentMethod === 'SculptCoins' ? 'sculptcoins' : 'points';
        if (users[userIndex].currencies[currencyKey] < paymentAmount) {
            return res.status(402).json({ message: `Insufficient ${paymentMethod}.` });
        }
        users[userIndex].currencies[currencyKey] -= paymentAmount;
        const testHubData = await getTestHubData();
        const newJob = { id: `job_${Date.now()}`, posterUsername: username, title, description, gameLink, requirements, paymentAmount, paymentMethod, status: 'open', testerUsername: null, applicants: [], chat: [], reports: [] };
        testHubData.jobs.push(newJob);
        testHubData.escrow[newJob.id] = { amount: paymentAmount, currency: paymentMethod };
        await saveUsers(users);
        await saveTestHubData(testHubData);
        res.status(201).json({ success: true, message: "Job posted successfully! Payment is now in escrow." });
    } catch (error) {
        console.error("Error posting job:", error);
        res.status(500).json({ message: "Server error while posting job." });
    }
});

app.get('/testhub/jobs', async (req, res) => {
    try {
        const testHubData = await getTestHubData();
        const openJobs = testHubData.jobs.filter(job => job.status === 'open');
        res.json({ success: true, jobs: openJobs });
    } catch (error) {
        res.status(500).json({ message: "Server error fetching jobs." });
    }
});

app.get('/testhub/messages', async (req, res) => {
    try {
        const { username } = req.query;
        if (!username) return res.status(400).json({ message: 'Username is required.' });
        const testHubData = await getTestHubData();
        const relevantJobs = testHubData.jobs.filter(job => job.posterUsername === username || job.testerUsername === username || job.applicants.some(app => app.username === username));
        res.json({ success: true, jobs: relevantJobs });
    } catch(error) {
        res.status(500).json({ message: 'Server error fetching messages.' });
    }
});

app.post('/testhub/apply', async (req, res) => {
    try {
        const { username, jobId } = req.body;
        const testHubData = await getTestHubData();
        const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId);
        if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' });
        const job = testHubData.jobs[jobIndex];
        if (job.posterUsername === username) return res.status(400).json({ message: "You cannot apply to your own job." });
        if (job.applicants.some(app => app.username === username)) return res.status(409).json({ message: "You have already applied." });
        const firstMessage = `Hello! I'm interested in testing your game.`;
        job.applicants.push({ username });
        job.chat.push({ sender: username, text: firstMessage, timestamp: new Date().toISOString() });
        await saveTestHubData(testHubData);
        res.json({ success: true, message: "Application sent!" });
    } catch (error) {
        res.status(500).json({ message: "Server error during application." });
    }
});

app.post('/testhub/message', async (req, res) => {
    try {
        const { username, text, jobId } = req.body;
        const testHubData = await getTestHubData();
        const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId);
        if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' });
        testHubData.jobs[jobIndex].chat.push({ sender: username, text: text, timestamp: new Date().toISOString() });
        await saveTestHubData(testHubData);
        res.json({ success: true, message: "Message sent." });
    } catch (error) {
        res.status(500).json({ message: "Server error sending message." });
    }
});

app.post('/testhub/accept', async (req, res) => {
    try {
        const { adminUsername, applicantUsername, jobId } = req.body;
        const testHubData = await getTestHubData();
        const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId);
        if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' });
        const job = testHubData.jobs[jobIndex];
        if (job.posterUsername !== adminUsername) return res.status(403).json({ message: "Unauthorized." });
        if (job.status !== 'open') return res.status(400).json({ message: "This job is not open for applications." });
        job.status = 'in_progress';
        job.testerUsername = applicantUsername;
        job.chat.push({ sender: 'System', text: `${applicantUsername} has been accepted as the tester.`, timestamp: new Date().toISOString() });
        await saveTestHubData(testHubData);
        res.json({ success: true, message: `${applicantUsername} accepted!` });
    } catch (error) {
        res.status(500).json({ message: "Server error while accepting applicant." });
    }
});

app.post('/testhub/submit-report', upload.array('attachments'), async (req, res) => {
    try {
        const { username, jobId, title, findings } = req.body;
        const testHubData = await getTestHubData();
        const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId);
        if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' });
        const job = testHubData.jobs[jobIndex];
        if (job.testerUsername !== username) return res.status(403).json({ message: "You are not the tester for this job." });
        const newReport = { id: `report_${Date.now()}`, title, findings, attachments: req.files ? req.files.map(file => `/uploads/${file.filename}`) : [], timestamp: new Date().toISOString() };
        job.reports.push(newReport);
        job.chat.push({ sender: 'System', text: `${username} submitted a new test report: "${title}"`, timestamp: new Date().toISOString() });
        await saveTestHubData(testHubData);
        res.json({ success: true, message: "Test report submitted!" });
    } catch (error) {
        res.status(500).json({ message: "Server error submitting report." });
    }
});

app.post('/testhub/complete-job', async (req, res) => {
    try {
        const { adminUsername, jobId } = req.body;
        const testHubData = await getTestHubData();
        const jobIndex = testHubData.jobs.findIndex(j => j.id === jobId);
        if (jobIndex === -1) return res.status(404).json({ message: 'Job not found.' });
        const job = testHubData.jobs[jobIndex];
        if (job.posterUsername !== adminUsername) return res.status(403).json({ message: "Unauthorized." });
        if (job.status !== 'in_progress') return res.status(400).json({ message: "Job is not in progress." });
        const escrowedPayment = testHubData.escrow[jobId];
        if (!escrowedPayment) return res.status(500).json({ message: "Critical error: Escrow data not found." });
        const users = await getUsers();
        const testerIndex = users.findIndex(u => u.username === job.testerUsername);
        if (testerIndex === -1) return res.status(404).json({ message: "Tester account not found." });
        const currencyKey = escrowedPayment.currency === 'SculptCoins' ? 'sculptcoins' : 'points';
        users[testerIndex].currencies[currencyKey] += escrowedPayment.amount;
        job.status = 'completed';
        delete testHubData.escrow[jobId];
        await saveUsers(users);
        await saveTestHubData(testHubData);
        res.json({ success: true, message: `Payment of ${escrowedPayment.amount} ${escrowedPayment.currency} has been released to ${job.testerUsername}.` });
    } catch (error) {
        res.status(500).json({ message: "Server error while completing job." });
    }
});

// --- Start Server ---
app.listen(PORT, async () => {
    await initializeData();
    console.log(`Server is running at http://localhost:${PORT}`);
});