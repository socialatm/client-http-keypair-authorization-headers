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
export declare class HttpKeyPairAuthorizator {
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
    createMessageSignature(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, hashAlgorithm: string, authorizationParameters: Record<string, any>, requiredAuthorizationHeaders?: string[]): string;
    createAuthorizationHeader(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, keyId: string, hashAlgorithm: string, authorizationParameters: Record<string, any>, requiredAuthorizationHeaders: string[]): string;
    createDigestHeader(text: string, hashAlgorithm: string): string;
}
export {};
