var mongoose = require('mongoose');
var Schema = mongoose.Schema;

const env = require('dotenv');
const bcrypt = require('bcryptjs');
env.config()

var userSchema = new Schema({
    "username": {
        type: String,
        unique: true
    },
    "password": String,
    "email": String,
    "loginHistory": [{
        "dateTime": Date,
        "userAgent": String
    }]
})

let User;

module.exports.initialize = function () {
    return new Promise((resolve, reject) => {
        let db = mongoose.createConnection(process.env.MONGO_URI_STRING);

        db.on('error', (err) => {
            reject(err); 
        });
        db.once('open', () => {
            console.log("MONGO DATABASE CONNECTED!")
            User = db.model("users", userSchema);
            resolve();
        });
    });
};

module.exports.registerUser = function (userData) {
    return new Promise((resolve, reject) => {
        if (userData.password != userData.password2) {
            reject("PASSWORDS DO NOT MATCH!")
        } else {
            bcrypt.hash(userData.password, 10).then((hash) => {
                userData.password = hash
                let newUser = new User(userData);
                newUser.save().then(() => {
                    resolve()
                }).catch((err) => {
                    if (err.code == 11000) {
                        reject("USERNAME IS TAKEN")
                    } else {
                        reject(err)
                    }
                })
            }).catch((err) => {
                console.log(err)
                reject("ERROR WITH PASSWORD ENCRYPTION")
            })

        }
    })
}

module.exports.loginUser = function (userData) {
    return new Promise((resolve, reject) => {
        User.findOne({ username: userData.username })
            .exec()
            .then((user) => {
                if (!user) {
                    reject("UNABLE TO FIND USER: " + userData.username)
                } else {
                    bcrypt.compare(userData.password, user.password).then((result) => {
                        if (result === true) {
                            user.loginHistory.push({ dateTime: new Date(), userAgent: userData.userAgent })
                            User.updateOne({ username: user.username }, {
                                $set: { loginHistory: user.loginHistory }
                            }).exec()
                                .then(() => {
                                    resolve(user)
                                }).catch((err) => {
                                    reject("ERROR UPDATING LOGIN HISTORY")
                                })

                        } else {
                            reject("UNABLE TO AUTHENTICATE USER: " + userData.username)
                        }
                    }).catch((err) => {
                        reject("DECRYPTION ERROR")
                    })
                }
            }).catch((err) => {
                reject("UNABLE TO FIND USER: " + userData.username)
            })
    })
}

