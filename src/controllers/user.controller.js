import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {user} from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import jwt from 'jsonwebtoken'
import mongoose from "mongoose"

const genrateAccessAndRefreshToken = async (userId) => {
    try {
        const User = await user.findById(userId)
        const accessToken = User.generateAccessToken()
        const refreshToken = User.generateRefreshToken()
        
        User.refreshToken = refreshToken
        await User.save({validateBeforeSave: false})
        
        return {accessToken,refreshToken}
        
    } catch (error) {
        throw new ApiError(500,"Something went wrong while genreting access and refresh token")
    }
}

const registerUser = asyncHandler(async (req,res) => {
    //get user details from frontend
    //validation - not empty
    //check if user already exits - username , email
    //check for images , check for avatar
    //upload them to cloudinary , avatar
    //create user object - create entry in db
    //remove password and refresh token field from response
    //check for user creation 
    //return res

    const {fullname, username, email,password} = req.body
    // console.log("Email: ",email);

    if(
        [fullname,email,username,password].some((field) => field?.trim() === "")
    )
    {
        throw new ApiError(400,"All fields are required")
    }

    const exitedUser = await user.findOne({
     $or: [{email},{username}] 
    })

    // console.log(exitedUser)

    if(exitedUser){
        throw new ApiError(409,"User with email and username already exits")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }
    
    // console.log(avatarLocalPath)
    // console.log("Avatar file object:", req.files?.avatar?.[0]);

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required")
    }
 
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400,"Avatar file is required")
    }
    
    const User = await user.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await user.findById(User._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registring the user")
    }
    
    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registred successfully")
    )


    
})

const loginUser = asyncHandler(async (req, res) => {
    //req body -> data
    //username , email
    //find the user
    //password check 
    //access and refresh token
    //send cookies

    const {email,username,password} = req.body

    if(!(email || username)){
        throw new ApiError(400,"Username or email is required")
    }

    const User = await user.findOne({
        $or: [{username},{email}]
    })

    if(!User){
        throw new ApiError(404,"User does not exist")
    }

    const isPasswordValid = await User.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401,"User Invalid Creditionals")
    }

    const {accessToken,refreshToken} = await genrateAccessAndRefreshToken(User._id)
    
    const loggedInUser = await user.findById(User._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken)
    .cookie("refreshToken",refreshToken)
    .json(
         new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully"
         )
    )


})

const logoutUser = asyncHandler(async (req,res) => {
    await user.findByIdAndUpdate(
        req.User._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            returnDocument: 'after'
        }
    )
     
    const options = {
        httpOnly: true,
        secure: true
    }

    res.status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(
        new ApiResponse(200, {} , "User Log Out")
    )

})

const refreshAccessToken = asyncHandler(async (req,res) =>{
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    
         if(!incomingRefreshToken){
            throw new ApiError(401,"unauthorized request")
         }
    
         const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
         )
    
         const User = await user.findById(decodedToken?._id)
    
         if(!User){
            throw new ApiError(401,"Invalid Refresh Token")
         }
    
         if(incomingRefreshToken != User?.refreshToken){
            throw new ApiError(401,"Refresh Token is expired or used")
         }
    
         const options = {
            httpOnly: true,
            secure: true
         }
    
         const {accessToken, newRefreshToken} = await genrateAccessAndRefreshToken(User._id)
    
         res.status(200)
         .cookie("accessToken",options)
         .cookie("newRefreshToken",options)
         .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken : newRefreshToken},
                "Access Token Refreshed"
            )
         )
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid Refresh Token")
    }
})

const changeCurrentPassword = asyncHandler(async (req,res) => {
    const {oldPassword, newPassword} = req.body

    const User = await user.findById(req.User._id)
    const isPasswordCorrect = await User.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(401,"Invalid Old Password")
    }

    User.password = newPassword
    await User.save({validateBeforeSave: false})

    res.status(200)
    .json(
        new ApiResponse(200, {}, "Password Changed Successfully")
    )
})

const getCurrentUser = asyncHandler(async(req,res) => {
    res.status(200)
    .json(200,req.User,"current user fetched successfully")
})

const updateAccountDetails = asyncHandler(async(req,res) => {
    const {fullname,email} = req.body

    if(!(fullname || email)){
        throw new ApiError(401,"All feilds are required")
    }

    const User = await user.findByIdAndUpdate(
        req.User?._id,
        {
            $set: {
                fullname,
                email
            }
        }, {returnDocument: 'after'}
    )

    res.status(200)
    .json(new ApiResponse(200,User,"Account Details Update Successfully"))
})

const updateUserAvatar = asyncHandler(async (req,res) => {
      const avtarLocalPath = req.file?.path

      if(!avtarLocalPath){
        throw new ApiError(400,"Avtar file is missing")
      }

      const avtar = await uploadOnCloudinary(avtarLocalPath)
      
      if(!avtar.url){
        throw new ApiError(400,"Error while uploading on avtar")
      }

      const User = await user.findByIdAndUpdate(req.User?._id,
        {
            $set: {
                avtar: avtar.url
            }
        },
        {returnDocument:'after'}
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200,User,"User Avtar update successfully"))
})

const updateUserCoverImage = asyncHandler(async (req,res) => {
      const coverImageLocalPath = req.file?.path

      if(!coverImageLocalPath){
        throw new ApiError(400,"Cover Image file is missing")
      }

      const coverImage = await uploadOnCloudinary(coverImageLocalPath)
      
      if(!coverImage.url){
        throw new ApiError(400,"Error while uploading on Cover Image")
      }

      const User = await user.findByIdAndUpdate(req.User?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {returnDocument:'after'}
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200,User,"User Cover Image update successfully"))
})

const getUserChannelProfile = asyncHandler(async (req,res) => {
    const {username} = await req.params

    if(!username?.trim()){
        throw new ApiError(400,"Username is missing")
    }

    const channel = user.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelSubcribedToCount: {
                    $size: "subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if : {$in: [req.user?._id,"%subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullname: 1,
                username: 1,
                subscribersCount: 1,
                channelSubcribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                createdAt: 1,
            }
        }

    ])

    if(!channel?.length){
        throw new ApiError(404,"channel does not exit")
    }

    return res.status(200)
    .json(
        new ApiResponse(200,channel[0],"Channel Fetched Successfully")
    )
})

const getWatchHistory = asyncHandler(async (req,res) => {
    const User = await user.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user?._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from:"users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullname: 1,
                                        username: 1,
                                        avtar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            $first: "$owner"
                        }
                    }
                ]
            }
        }
    ])

    return res.status(200)
    .json(
        new ApiResponse(200,User[0].watchHistory,"watch history fetched successfully")
    )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}