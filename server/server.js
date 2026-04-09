import express from 'express';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcrypt';
import User from './Schema/User.js';

const server = express();

let PORT =  3000;

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true,
});

server.post("/signup", (req, res) => {
    let { fullname, email, password } = req.body;
    // validating the data from frontend
    if(fullname.length < 3){
        return res.status(403).json({ error: "Fullname must be at least 3 characters long" });
    }
    if(!email.length){
        return res.status(403).json({ error: "Enter Email" });
    }
    if(!emailRegex.test(email)){
        return res.status(403).json({ error: "Enter Valid Email" });
    }
    if(!passwordRegex.test(password)){
        return res.status(403).json({ error: "Password must be between 6 to 20 characters and contain at least one numeric digit, one uppercase and one lowercase letter" });
    }
    bcrypt.hash(password, 10, (err, hashed_Password) => {
        let username = email.split("@")[0];
        let user = new User({
            personal_info: { fullname, email, password: hashed_Password, username }
        })
        user.save().then((u) => {
            return res.status(200).json({ user: u });
        }).catch(err => {
            if(err.code == 11000){
                return res.status(500).json({ "error": "Email already exists" });
            }
            return res.status(500).json({ error: err.message });
        })
        console.log(hashed_Password);
    });
    return res.status(200).json({ "status": "okay" });
})

server.listen(PORT, () => {
    console.log('listening on port ' + PORT);
})