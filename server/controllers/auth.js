const { connect } = require('getstream');
const bcrypt = require('bcrypt');
const StreamChat = require('stream-chat').StreamChat;
const crypto = require('crypto');

require('dotenv').config();

const api_key = process.env.STREAM_API_KEY;
const api_secret = process.env.STREAM_API_SECRET;
const app_id = process.env.STREAM_APP_ID;

const signup = async (req, res) => {
  try {
    //lay data tu form
    const { fullName, username, password, phoneNumber } = req.body;
    //tao userId moi
    const userId = crypto.randomBytes(16).toString('hex');
    //Tao client ket noi voi getstream
    const serverClient = connect(api_key, api_secret, app_id);
    //Ma hoa cho mat khau cua userId
    const hashedPassword = await bcrypt.hash(password, 10);
    //Tao token cho userId
    const token = serverClient.createUserToken(userId);

    res
      .status(200)
      .json({ token, hashedPassword, userId, fullName, username, phoneNumber });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error });
  }
};

const login = async (req, res) => {
  try {
    //lay data tu form dang nhap
    const { username, password } = req.body;
    //ket noi getstream client
    const serverClient = connect(api_key, api_secret, app_id);
    //import streamchat client
    const client = StreamChat.getInstance(api_key, api_secret);
    //tao danh sach user match voi name trong username
    const { users } = await client.queryUsers({ name: username });
    //neu danh sach user k match thi return not found
    if (!users.length)
      return res.status(400).json({ message: 'User not found' });
    //Tao dieu kien dang nhap thanh cong bang cach dung bcrypt so sanh password va hashedPassword da luu
    const success = await bcrypt.compare(password, users[0].hashedPassword);
    //tao token dang nhap moi
    const token = serverClient.createUserToken(users[0].id);
    //neu dieu kien dang nhap thanh cong
    if (success) {
      res.status(200).json({
        token,
        fullName: users[0].fullName,
        username,
        userId: users[0].id,
      });
    } else {
      res.status(500).json({ message: 'Incorrect password' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error });
  }
};

module.exports = { signup, login };
