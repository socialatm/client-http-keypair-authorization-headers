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
    static createSigningMessage(httpRequest: HttpRequest, authorizationParameters?: Record<string, any>): string;
    static createMessageSignature(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string, any>): string;
    static createAuthorizationHeader(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string, any>): string;
    static createDigestHeader(text: string, hashAlgorithm: string): string;
    static digestHttpRequest(httpRequest: HttpRequest, hashAlgorithm: string): HttpRequest;
    static signHttpRequest(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string, any>, digestHashAlgorithm?: string): HttpRequest;
    static doesDigestVerify(text: string, digest: string): boolean;
    static doesSignatureHeaderVerify(header: string, httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean;
    static doesHttpRequestVerify(httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean;
    static getAuthorizationParametersFromSignatureHeader(signatureHeader: string): Record<string, any>;
    static __getRequestTarget(httpRequest: HttpRequest): string;
    static exportPrivateKeyToPemString(privateKey: typeof crypto.PrivateKeyObject): string;
    static exportPublicKeyToPemString(publicKey: typeof crypto.PublicKeyObject): string;
    static importPrivateKeyFromPemString(pemString: string, algorithmParameters: any): typeof crypto.PrivateKeyObject;
    static importPublicKeyFromPemString(pemString: string, algorithmParameters: any): typeof crypto.PublicKeyObject;
}
export {};
