import mongoose, {Schema} from "mongoose";

const subscriptionSchema = new Schema({
    subscriber: {
        type: mongoose.Schema.Types.ObjectId, //one who is subscribing
        ref: "User",
    },
    channel: {
        type: mongoose.Schema.Types.ObjectId, //one who is being subscribed to
        ref: "User",
    }

},{timestamps: true})

export const subscription = mongoose.model("Subscription", subscriptionSchema)