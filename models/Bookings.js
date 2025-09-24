const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema(
    {
        guideEmail: {
            type: String,
            required: true,
            index: true,
        },
        guideName: {
            type: String,
            required: true,
        },
        userEmail: {
            type: String,
            required: true,
        },
        userName: {
            type: String,
            required: true,
        },
        date: {
            type: Date,
            required: true,
        },
        status: {
            type: String,
            enum: ["Pending", "Confirmed", "Rejected", "Completed", "Cancelled"],
            default: "Pending",
        },
        notes: {
            type: String,
            default: "",
        },
        price: {
            type: Number,
            default: 0,
        },
        paidAmount: {
            type: Number,
            default: 0,
        },
        balanceAmount: {
            type: Number,
            default: 0,
        },
        paymentDetails: {
            paymentId: String,
            orderId: String,
            signature: String,
            paidAt: Date,
        },
    },
    { timestamps: true }
);

module.exports = mongoose.model("Booking", bookingSchema);
