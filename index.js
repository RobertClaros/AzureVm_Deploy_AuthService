const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 8080;

const uri = "mongodb+srv://audioprobolivia:znlz4KRkSJUy0SWD@cluster0.i33ai1o.mongodb.net/?retryWrites=true&w=majority";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

app.use(express.json());

const registerUser = async (username, password) => {
  try {
    const specialCharacters = /[!@#$%^&*(),.?":{}|<>]/;
    if (specialCharacters.test(username)) {
      throw new Error('Invalid username');
    }

    const db = client.db();
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      throw new Error('User already registered');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').insertOne({ username, password: hashedPassword });

    return { success: true, message: 'Registration successful' };
  } catch (error) {
    console.error(error);
    if (error.message === 'Invalid username') {
      return { success: false, message: 'Invalid username' };
    }
    return { success: false, message: 'Registration failed' };
  }
};

const loginUser = async (username, password) => {
  try {
    const db = client.db();
    const user = await db.collection('users').findOne({ username });
    if (!user) {
      throw new Error('Invalid username or password');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new Error('Invalid username or password');
    }

    const token = jwt.sign({ username }, 'mySecretKey');
    
    return { success: true, token };
  } catch (error) {
    console.error(error);
    return { success: false, message: 'Login failed' };
  }
};

const authenticateToken = async (token) => {
  try {
    const decoded = jwt.verify(token, 'mySecretKey');
    return { success: true, user: decoded };
  } catch (error) {
    console.error(error);
    return { success: false, message: 'Invalid token' };
  }
};

const router = express.Router();

router.get('/', async (req, res) => {
  res.send('Connection to AuthService successful');
});

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const result = await registerUser(username, password);
  if (result.success) {
    res.status(201).json({ message: result.message });
  } else {
    res.status(400).json({ message: result.message });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await loginUser(username, password);
  if (result.success) {
    res.json({ token: result.token });
  } else {
    res.status(401).json({ message: result.message });
  }
});

router.get('/validated', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token is required' });
  }

  const result = await authenticateToken(token);
  if (result.success) {
    res.json({ message: 'Route validated', user: result.user });
  } else {
    res.status(403).json({ message: result.message });
  }
});

app.use(router);

app.listen(PORT, () => {
  console.log(`Server start at http://localhost:${PORT}`);
});
