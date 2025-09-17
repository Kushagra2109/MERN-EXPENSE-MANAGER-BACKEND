import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
// import bodyParser from 'body-parser';
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer"

dotenv.config();
const PORT = process.env.PORT;
const MONGODB_URL = process.env.MONGO_URI;

const app = express();
app.use(cors());
app.use(express.json());

app.listen(PORT, async () => {
  console.log(`app listening on port ${PORT}`);
  await mongoose.connect(MONGODB_URL).then(() => {
    console.log("connected to database");
  });
});

const authenticate = async (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    return res.status.json({ message: "user not logged in" });
  }

  const decode = jwt.verify(token, process.env.SECRET_CODE);
  req.user = decode;
  next();
};

const mongoSchema = new mongoose.Schema({
  txnType: String,
  amount: Number,
  category: String,
  desc: String,
  user: mongoose.Schema.Types.ObjectId,
  date: { type: Date, default: Date.now },
});

const txns = mongoose.model("transactions", mongoSchema);

app.get("/gettxns", authenticate, async (req, res) => {
  try {
    const result = await txns.find({ user: req.user._id });
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch transactions!" });
  }
});

app.post("/addtxn", authenticate, async (req, res) => {
  try {
    const result = await txns.create({ ...req.body, user: req.user._id });
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ message: "Failed to add transaction" });
  }
});

app.put("/updatetxn/:id", authenticate, async (req, res) => {
  try {
    const result = await txns.findByIdAndUpdate(
      { _id: req.params.id, user: req.user._id },
      { $set: req.body },
      { new: true }
    );
    res.status(200).json(result);
  } catch {
    res.status(404).json({ message: "Failed to update transaction!" });
  }
});

app.delete("/deletetxn/:id", authenticate, async (req, res) => {
  try {
    const result = await txns.findByIdAndDelete({
      _id: req.params.id,
      user: req.user._id,
    });
    res.status(200).json({ message: "Transaction Deleted Successfully!!" });
  } catch {
    res.status(500).json({ message: "Failed to delete the transaction!" });
  }
});

const UserSchema = new mongoose.Schema({
  email : String,
  username: String,
  password: String,
});

const user = mongoose.model("users", UserSchema);

app.post("/registerUser", async (req, res) => {
  try {
    const exists = await user.findOne({ email: req.body.email });
    if (exists) {
      return res.status(409).json("user already exits");
    }

    const hashedPass = await bcrypt.hash(req.body.password, 10);

    const data = await user.create({
      email : req.body.email,
      username: req.body.username,
      password: hashedPass,
    });
    res.status(200).json({ message: "User Successfully Registered!!" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/loginuser", async (req, res) => {
  const exists = await user.findOne({ username: req.body.username });
  if (!exists) {
    return res.json("incorrect username!!");
  }

  const validatePassword = await bcrypt.compare(
    req.body.password,
    exists.password
  );

  if (!validatePassword) {
    return res.json("incorrect password!!");
  }

  const token = jwt.sign(
    { _id: exists._id, username: exists.username },
    process.env.SECRET_CODE
  );
  res.json({ token: token });
});


app.post('/forgotPassword' , async (req , res) => {
    const resultUser = await user.findOne({email : req.body.email});

    if(!resultUser){
        res.status(404).json({message : "This email is not associated with a Registered user!"})
    }

    const token  = jwt.sign({id : resultUser._id} , process.env.RESET_CODE, {expiresIn : "15m"});

    const frontend_uri = process.env.FRONTEND_URI;
    const resetURL = `${frontend_uri}/resetpassword/${token}`;

    const transporter = nodemailer.createTransport({
      service : 'gmail', 
      auth : {
        user : process.env.GMAIL,
        pass : process.env.GMAIL_PASSWORD
      }
    })

    await transporter.sendMail({
      from : process.env.GMAIL,
      to : req.body.email,
      subject : "PASSWORD RESET LINK FROM KS EXPENSE MANAGER",
      html : `<h3>Reset Your Password</h3>
      <p>You can reset your password using the link below:</p>
      <a href= ${resetURL} target="_blank">${resetURL}</a>
      <p>This link is valid only for 15 minutes.</p>`
    })
    console.log("success")
    res.status(200).json({message : "password reset link sent to your email!!"})

    
})

app.get("/reset-password/:token", async (req , res) => {
  try{
    const decoded =  jwt.verify(req.params.token , process.env.RESET_CODE)
    res.status(200).json({message :"token valid"})
  }
  catch(err){
    res.status(500).json({message : "token invalid!"})
  }
})

app.post(`/updatePassword/:token` , async (req , res) => {
  try{
  const updatedPassword = req.body.password;
  const token = req.params.token;

  const decode = jwt.verify(token , process.env.RESET_CODE)
  const userToBeUpdated = await user.findById(decode.id);

  if(!userToBeUpdated){
    return res.status(404).json({message : "User not found!"})
  }

  const newHashedPassword = await bcrypt.hash(updatedPassword , 10);

  userToBeUpdated.password = newHashedPassword;
  await userToBeUpdated.save();

  res.status(200).json({message : "Password Successfully updated!!"})
}
catch(err){
  res.status(500).json({message : "Something went wrong!"})
}
})