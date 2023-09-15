const express = require('express');
const app = express();
app.use(express.json());

const dotenv = require('dotenv');
dotenv.config()

const jwt = require('jsonwebtoken');




const User = [
    {
        id: 1,
        username: 'love123',
        password: 'love123Love',
        email: 'love@gmail.com',
        isAdmin: true
    },

    {
        id: 2,
        username: 'vicky123',
        password: 'vicky123Vicky',
        email: 'vicky@gmail.com',
        isAdmin: false
    }

];

const refreshTokens = [];


const getAccessToken = (user)=>{
    return jwt.sign(
        {
            id: user.id,
            isAdmin: user.isAdmin
        },
        process.env.TOKEN_KEY,
        {expiresIn: '20sec'}
    )
}

const getRefreshToken = (user)=>{
    return jwt.sign(
        {
            id:user.id,
            isAdmin: user.isAdmin
        },
        process.env.REFRESH_TOKEN_KEY
    )
}

app.post('/api/login', (req,res)=>{
    const {username, password} = req.body;
    const user = User.find((user)=>{
        return (user.username === req.body.username && user.password === req.body.password)
    });

    if(user){
        // this is the very unsecured way to login
        // res.status(200).json(user);

        // More secured way is after the login credential match
        // Generate JWT token
        const accessToken = getAccessToken(user);
        const refreshToken = getRefreshToken(user);
        refreshTokens.push(refreshToken);
        res.status(200).json({
            username:user.username,
            isAdmin:user.isAdmin,
            accessToken,
            refreshToken
        })
    }else{
        res.status(400).json('user or password is incorrect')
    }
});

app.post('/api/refresh',(req,res)=>{
    // take the refrence token from the user
    const refreshToken = req.headers.authorization;

    // send error if there is no token or invalid token
    if(!refreshToken) res.status(401).json('You are not authenticated');

    if(!refreshTokens.includes(refreshToken)) res.status(403).json('Refresh token is invalid');

    // if everything is ok, create new access token, refresh token, and send to user
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_KEY,
        (err,user)=>{
            if(err) console.log(err);
            // if err, log it to the console
            // err && console.log(err);

            else{
                refreshTokens.filter((token)=>token !== refreshToken);

                const newAccessToken = getAccessToken(user);
                const newRefreshToken = getRefreshToken(user);

                refreshTokens.push(newRefreshToken);

                res.status(200).json(
                    newAccessToken,
                    newRefreshToken
                )

            }  
        }
    )
});

// verify token
const verify = (req,res,next)=>{
    const authHeader = req.headers.authorization;

    if(authHeader){
        const token = authHeader.split(' ')[1];
        jwt.verify(
            token,
            process.env.TOKEN_KEY,
            (err,user)=>{
                if (err){
                    console.log('The token is not valid');
                }
                req.user = user;
                next();
            }
        )

    }else{
        res.status(401).json('You are not authenicated.')
    }
}

app.delete('/api/delete/:userId', verify, (req,res)=>{
    if(req.user?.id === req.params.userId || req.user?.isAdmin){
        return res.status(200).json('User is deleted sucessfully!');
    }else{
        return res.status(403).json('You cannot delete user')
    }
});



app.listen(3000,()=> console.log('The Server is up and running'))