// helpers/sendNotification.js
const webpush = require('web-push');
const UserSubscription = require('../models/UserSubscription');

async function sendNotification(targetEmail, payload) {
    try {
        const subscriptionDoc = await UserSubscription.findOne({ email: targetEmail });
        if (!subscriptionDoc) {
            console.log(`❌ No subscription found for ${targetEmail}`);
            return;
        }

        await webpush.sendNotification(subscriptionDoc.subscription, JSON.stringify(payload));
        console.log(`✅ Notification sent to ${targetEmail}`);
    } catch (err) {
        console.error(`❌ Failed to send notification to ${targetEmail}:`, err);
    }
}

module.exports = sendNotification;
