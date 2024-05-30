import { asyncHandeler } from "../utils/asyncHandeler.js";
import { ApiError } from "../utils/ApiErrors.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken}
    } catch (error) {
        throw new ApiError(500,"something went wrong while generating refresh and access token")    
    }
}

const registerUser = asyncHandeler(async (req,res)=>{
    // get user details from frontend
    // validation -not empty
    // check if user already exist -username,email
    // check for emages,check for avatar
    // upload them to cloudinary
    // create user object -create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return response

    const {fullname,email,username,password}=req.body
    // console.log("email : ",email);

    if (
        [fullname,email,username,password].some((field)=>field?.trim()==="")
    ) {
        throw new ApiError(400,"All fields are required")
    }

   const existedUser = await User.findOne({
        $or :[{ username },{ email }] 
    })

    if(existedUser){
        throw new ApiError(409,"User with email or username already exists")
    }
    // console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalPath) {
        throw new ApiError(400,"Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400,"Avatar file is required")
    }

    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username:username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered successfully")
    )
    
})

const loginUser = asyncHandeler(async (req,res)=>{
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token
    // send cookie

    const {email,username,password} = req.body
    // console.log(email);

    if(!username && !email){
        throw new ApiError(400,"username or email is required")
    }

    // alternative of above code
    // if(!username || !email){
    //     throw new ApiError(400,"username or email is required")
    // }

    const user = await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(404,"User does not exist")
    }

    const isPasseordValid = await user.isPasswordCorrect(password)

    if(!isPasseordValid){
        throw new ApiError(401,"Password incorrect")
    }

    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly : true,
        secure : true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser,accessToken,refreshToken
            },
            "User loggedIn successfully"
        )
    )

})

const logoutUser = asyncHandeler(async(req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set : {
                refreshToken:undefined
            }
        },
        {
            new : true
        }
    )

    const options = {
        httpOnly : true,
        secure : true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200),{},"User logged Out")
})

const refresAccessToken = asyncHandeler(async(req,res)=>{
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

    if(incomingRefreshToken){
        throw new ApiError(401,"unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401,"Refresh token is expired or used")
        }
    
        const options = {
            httpOnly:true,
            secure:true
        }
    
        const {accessToken,newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken,refreshToken:newRefreshToken},
                "Access token refreshed"
            )
        )
    
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid refresh token")
    }
})
export {
    registerUser,
    loginUser,
    logoutUser,
    refresAccessToken
}