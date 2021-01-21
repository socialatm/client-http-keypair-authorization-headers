declare const crypto: any;
export interface HttpHeaders {
    [key: string]: string;
}
export declare enum HttpMethod {
    Get = "GET",
    Post = "POST",
    Put = "PUT",
    Patch = "PATCH",
    Update = "UPDATE",
    Delete = "DELETE",
    Options = "OPTIONS",
    Head = "HEAD"
}
export interface HttpRequest {
    method: HttpMethod;
    path: string;
    headers: HttpHeaders;
    body: string;
}
export default class HttpKeyPairAuthorizer {
    modulusLength: number;
    publicKeyType: string;
    privateKeyType: string;
    privateKeyFormat: string;
    privateKeyCipher: string;
    private __privateKeyPassphrase;
    defaultPassphraseLength: number;
    constructor();
    get privateKeyPassphrase(): string;
    set privateKeyPassphrase(passphrase: string);
    generatePrivateKeyPassphrase(length?: number): string;
    createSigningMessage(httpRequest: HttpRequest, authorizationParameters?: Record<string, any>): string;
    createMessageSignature(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string, any>): string;
    createAuthorizationHeader(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string, any>): string;
    createDigestHeader(text: string, hashAlgorithm: string): string;
    digestHttpRequest(httpRequest: HttpRequest, hashAlgorithm: string): HttpRequest;
    signHttpRequest(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string, any>, digestHashAlgorithm?: string): HttpRequest;
    doesDigestVerify(text: string, digest: string): boolean;
    doesSignatureHeaderVerify(header: string, httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean;
    doesHttpRequestVerify(httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean;
    getAuthorizationParametersFromSignatureHeader(signatureHeader: string): Record<string, any>;
    __getRequestTarget(httpRequest: HttpRequest): string;
}
export {};
