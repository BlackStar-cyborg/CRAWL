// Returns all request headers as a JSON array of [name, value] pairs, in the order the client
// sent them. Header order is part of client fingerprints (e.g. JA4H), and it shows headers
// that the classic log formats never record (e.g. a Log4Shell payload in X-Api-Version).
function raw(r) {
    try {
        return JSON.stringify(r.rawHeadersIn);
    } catch (e) {
        return "[]";
    }
}

export default { raw };
