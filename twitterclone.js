const express = require('express')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, 'twitterClone.db')
let db = null

const initializeDB = async () => {
  db = await open({
    filename: dbPath,
    driver: sqlite3.Database,
  })
}

initializeDB()

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  if (!authHeader) return res.status(401).send('Invalid JWT Token')

  const token = authHeader.split(' ')[1]
  jwt.verify(token, 'SECRET_KEY', (error, payload) => {
    if (error) return res.status(401).send('Invalid JWT Token')
    req.username = payload.username
    next()
  })
}

// API 1: Register
app.post('/register/', async (req, res) => {
  const {username, password, name, gender} = req.body
  const user = await db.get(`SELECT * FROM user WHERE username = ?`, [username])

  if (user) return res.status(400).send('User already exists')
  if (password.length < 6) return res.status(400).send('Password is too short')

  const hashedPassword = await bcrypt.hash(password, 10)
  await db.run(
    `INSERT INTO user (username, password, name, gender) VALUES (?, ?, ?, ?)`,
    [username, hashedPassword, name, gender],
  )
  res.send('User created successfully')
})

// API 2: Login
app.post('/login/', async (req, res) => {
  const {username, password} = req.body
  const user = await db.get(`SELECT * FROM user WHERE username = ?`, [username])

  if (!user) return res.status(400).send('Invalid user')

  const isValid = await bcrypt.compare(password, user.password)
  if (!isValid) return res.status(400).send('Invalid password')

  const token = jwt.sign(
    {username: user.username, userId: user.user_id},
    'SECRET_KEY',
  )
  res.send({jwtToken: token})
})

// Helper: Get userId from username
const getUserId = async username => {
  const user = await db.get(`SELECT * FROM user WHERE username = ?`, [username])
  return user.user_id
}

// API 3: Latest tweets feed
app.get('/user/tweets/feed/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const tweets = await db.all(
    `SELECT user.username, tweet, date_time as dateTime
     FROM follower
     JOIN tweet ON tweet.user_id = follower.following_user_id
     JOIN user ON tweet.user_id = user.user_id
     WHERE follower.follower_user_id = ?
     ORDER BY date_time DESC
     LIMIT 4`,
    [userId],
  )
  res.send(tweets)
})

// API 4: Users followed
app.get('/user/following/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const following = await db.all(
    `SELECT name FROM user
     JOIN follower ON user.user_id = follower.following_user_id
     WHERE follower.follower_user_id = ?`,
    [userId],
  )
  res.send(following)
})

// API 5: Followers
app.get('/user/followers/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const followers = await db.all(
    `SELECT name FROM user
     JOIN follower ON user.user_id = follower.follower_user_id
     WHERE follower.following_user_id = ?`,
    [userId],
  )
  res.send(followers)
})

// Helper: Check if following tweet owner
const isFollowingTweetOwner = async (userId, tweetId) => {
  const tweet = await db.get(`SELECT user_id FROM tweet WHERE tweet_id = ?`, [
    tweetId,
  ])
  if (!tweet) return false
  const following = await db.get(
    `SELECT * FROM follower WHERE follower_user_id = ? AND following_user_id = ?`,
    [userId, tweet.user_id],
  )
  return following !== undefined
}

// API 6: Tweet details
app.get('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const {tweetId} = req.params

  const access = await isFollowingTweetOwner(userId, tweetId)
  if (!access) return res.status(401).send('Invalid Request')

  const tweet = await db.get(
    `SELECT tweet, date_time as dateTime,
       (SELECT COUNT(*) FROM like WHERE tweet_id = ?) AS likes,
       (SELECT COUNT(*) FROM reply WHERE tweet_id = ?) AS replies
     FROM tweet WHERE tweet_id = ?`,
    [tweetId, tweetId, tweetId],
  )
  res.send(tweet)
})

// API 7: Likes
app.get('/tweets/:tweetId/likes/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const {tweetId} = req.params

  const access = await isFollowingTweetOwner(userId, tweetId)
  if (!access) return res.status(401).send('Invalid Request')

  const result = await db.all(
    `SELECT username FROM user
     JOIN like ON user.user_id = like.user_id
     WHERE like.tweet_id = ?`,
    [tweetId],
  )
  res.send({likes: result.map(r => r.username)})
})

// API 8: Replies
app.get('/tweets/:tweetId/replies/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const {tweetId} = req.params

  const access = await isFollowingTweetOwner(userId, tweetId)
  if (!access) return res.status(401).send('Invalid Request')

  const replies = await db.all(
    `SELECT user.name, reply.reply FROM reply
     JOIN user ON reply.user_id = user.user_id
     WHERE tweet_id = ?`,
    [tweetId],
  )
  res.send({replies})
})

// API 9: All tweets of logged-in user
app.get('/user/tweets/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const tweets = await db.all(
    `SELECT tweet, date_time as dateTime,
     (SELECT COUNT(*) FROM like WHERE like.tweet_id = tweet.tweet_id) AS likes,
     (SELECT COUNT(*) FROM reply WHERE reply.tweet_id = tweet.tweet_id) AS replies
     FROM tweet WHERE user_id = ?`,
    [userId],
  )
  res.send(tweets)
})

// API 10: Post a tweet
app.post('/user/tweets/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const {tweet} = req.body

  await db.run(
    `INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, datetime('now'))`,
    [tweet, userId],
  )
  res.send('Created a Tweet')
})

// API 11: Delete tweet
app.delete('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  const userId = await getUserId(req.username)
  const {tweetId} = req.params

  const tweet = await db.get(`SELECT * FROM tweet WHERE tweet_id = ?`, [
    tweetId,
  ])
  if (!tweet || tweet.user_id !== userId)
    return res.status(401).send('Invalid Request')

  await db.run(`DELETE FROM tweet WHERE tweet_id = ?`, [tweetId])
  res.send('Tweet Removed')
})

// Default export
module.exports = app

