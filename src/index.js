// require('dotenv').config({path: './env'})
import dotenv from 'dotenv';
import connectDB from "./db/index.js";
import {app} from "./app.js"

dotenv.config({path: './env'})

connectDB()
.then(() => {
    app.listen(process.env.PORT || 8000 ,  () => {
        console.log(`server is running on port : ${process.env.PORT}`)
    })
})
.catch((error)=>{
     console.log("Mongodb connection failed !! ",error)
})

/*
import express from 'express';
const app = express();

(async () => {
    
    try {
        await mongoose.connect(`${process.env.MONGODB_URL}/${DB_NAME}`)
        app.on('error',(error) => {
            console.error('Error: ',error)
            throw err
        })

        app.listen(process.env.PORT, () => {
            console.log(`App is listning on port ${process.env.PORT}`)
        })

    } catch (error) {
        console.error('Error: ',error)
        throw err
    }

})()

*/