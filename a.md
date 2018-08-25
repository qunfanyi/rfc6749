
# 1. Introduction  
>[en]In the traditional client-server authentication model, the client requests an access-restricted resource (protected resource) on the server by authenticating with the server using the resource owner's credentials.  

在传统的客户机-服务器身份验证模型中，客户机通过使用资源所有者的凭证与服务器进行身份验证来请求服务器上的访问受限资源（受保护资源）。  

>[en]In order to provide third-party applications access to restricted resources, the resource owner shares its credentials with the third party.  

为了向第三方应用程序提供对受限资源的访问，资源所有者与第三方共享其凭据。  

>[en]This creates several problems and limitations: o Third-party applications are required to store the resource owner's credentials for future use, typically a password in clear-text.  

这产生了几个问题和限制：o第三方应用程序需要存储资源所有者的凭证以便将来使用，通常是明文的密码。  

>[en]o Servers are required to support password authentication, despite the security weaknesses inherent in passwords.  

O服务器需要支持密码验证，尽管密码中存在安全弱点。  

>[en]o Third-party applications gain overly broad access to the resource owner's protected resources, leaving resource owners without any ability to restrict duration or access to a limited subset of resources.  

o第三方应用程序获得对资源所有者的受保护资源的过于广泛的访问，使得资源所有者没有任何能力限制持续时间或对有限资源子集的访问。  

>[en]o Resource owners cannot revoke access to an individual third party without revoking access to all third parties, and must do so by changing the third party's password.  

o资源所有者不能在不撤销对所有第三方的访问的情况下撤销对单个第三方的访问，并且必须通过更改第三方的密码来这样做。  

>[en]Hardt Standards Track [Page 4] RFC 6749 OAuth 2.0 October 2012 o Compromise of any third-party application results in compromise of the end-user's password and all of the data protected by that password.  

硬标准跟踪[第4页]RFC 6749 OAuth 2.0 2012年10月2日o妥协任何第三方应用程序导致最终用户的密码和受该密码保护的所有数据的泄露。  

>[en]OAuth addresses these issues by introducing an authorization layer and separating the role of the client from that of the resource owner.  

OAuth通过引入授权层并将客户端角色与资源所有者的角色分离来解决这些问题。  

>[en]In OAuth, the client requests access to resources controlled by the resource owner and hosted by the resource server, and is issued a different set of credentials than those of the resource owner.  

在OAuthe中，客户端请求访问由资源所有者控制并由资源服务器托管的资源，并发出与资源所有者的不同的凭据集合。  

>[en]Instead of using the resource owner's credentials to access protected resources, the client obtains an access token -- a string denoting a specific scope, lifetime, and other access attributes.  

代替使用资源所有者的凭证来访问受保护的资源，客户端获得访问令牌——一个表示特定范围、生存期和其他访问属性的字符串。  

>[en]Access tokens are issued to third-party clients by an authorization server with the approval of the resource owner.  

访问令牌通过授权服务器向第三方客户端发布，并获得资源所有者的批准。  

>[en]The client uses the access token to access the protected resources hosted by the resource server.  

客户端使用访问令牌访问资源服务器托管的受保护资源。  

>[en]For example, an end-user (resource owner) can grant a printing service (client) access to her protected photos stored at a photo- sharing service (resource server), without sharing her username and password with the printing service.  

例如，终端用户（资源所有者）可以授权打印服务（客户端）访问存储在照片共享服务（资源服务器）中的她受保护的照片，而不用与打印服务共享她的用户名和密码。  

>[en]Instead, she authenticates directly with a server trusted by the photo-sharing service (authorization server), which issues the printing service delegation- specific credentials (access token).  

相反，她直接使用照片共享服务（授权服务器）信任的服务器进行身份验证，该服务器发出打印服务特定委托凭据（访问令牌）。  

>[en]This specification is designed for use with HTTP ([RFC2616]).  

本规范设计用于HTTP（[RCF2616]）。  

>[en]The use of OAuth over any protocol other than HTTP is out of scope.  

在HTTP以外的任何协议上使用OAutho都超出了范围。  

>[en]The OAuth 1.0 protocol ([RFC5849]), published as an informational document, was the result of a small ad hoc community effort.  

OAuth1协议（[RCF584]）作为一个信息文档发布，是一个小型的特设社区努力的结果。  

>[en]This Standards Track specification builds on the OAuth 1.0 deployment experience, as well as additional use cases and extensibility requirements gathered from the wider IETF community.  

此标准跟踪规范基于OAuth 1.0部署经验，以及从更广泛的IETF社区收集的附加用例和可扩展性需求。  

>[en]The OAuth 2.0 protocol is not backward compatible with OAuth 1.0.  

OAuth- 2协议不是向后兼容OAuth- 1。  

>[en]The two versions may co-exist on the network, and implementations may choose to support both.  

这两个版本可以共存于网络上，并且实现可以选择支持两者。  

>[en]However, it is the intention of this specification that new implementations support OAuth 2.0 as specified in this document and that OAuth 1.0 is used only to support existing deployments.  

然而，本规范的意图是，新的实现支持本文中指定的OAuth 2.0，并且OAuth 1.0仅用于支持现有部署。  

>[en]The OAuth 2.0 protocol shares very few implementation details with the OAuth 1.0 protocol.  

OAuth2协议与OAuth- 1协议共享很少的实现细节。  

>[en]Implementers familiar with OAuth 1.0 should approach this document without any assumptions as to its structure and details.  

熟悉OAuth1的实现者不必对其结构和细节进行任何假设就应接近该文档。  




## 1.1. Roles  
>[en]OAuth defines four roles: resource owner An entity capable of granting access to a protected resource.  

OAuTH定义了四个角色：资源所有者：能够授予受保护资源访问权限的实体。  

>[en]When the resource owner is a person, it is referred to as an end-user.  

当资源所有者是人时，它被称为最终用户。  

>[en]resource server The server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens.  

资源服务器托管受保护资源的服务器，能够使用访问令牌接受和响应受保护的资源请求。  

>[en]client An application making protected resource requests on behalf of the resource owner and with its authorization.  

客户端：代表资源所有者及其授权进行保护资源请求的应用程序。  

>[en]The term "client" does not imply any particular implementation characteristics (e.g., whether the application executes on a server, a desktop, or other devices).  

术语“客户端”并不意味着任何特定的实现特征（例如，应用程序是否在服务器、桌面或其他设备上执行）。  

>[en]authorization server The server issuing access tokens to the client after successfully authenticating the resource owner and obtaining authorization.  

授权服务器在成功认证资源所有者并获得授权之后，向客户端发布访问令牌的服务器。  

>[en]The interaction between the authorization server and resource server is beyond the scope of this specification.  

授权服务器和资源服务器之间的交互超出了本规范的范围。  

>[en]The authorization server may be the same server as the resource server or a separate entity.  

授权服务器可以是与资源服务器相同的服务器，也可以是独立的实体。  

>[en]A single authorization server may issue access tokens accepted by multiple resource servers.  

单个授权服务器可以发布由多个资源服务器接受的访问令牌。  




## 1.2. Protocol Flow  
>[en]+--------+ +---------------+ | |--(A)- Authorization Request ->| Resource | | | | Owner | | |<-(B)-- Authorization Grant ---| | | | +---------------+ | | | | +---------------+ | |--(C)-- Authorization Grant -->| Authorization | | Client | | Server | | |<-(D)----- Access Token -------| | | | +---------------+ | | | | +---------------+ | |--(E)----- Access Token ------>| Resource | | | | Server | | |<-(F)--- Protected Resource ---| | +--------+ +---------------+ Figure 1: Abstract Protocol Flow The abstract OAuth 2.0 flow illustrated in Figure 1 describes the interaction between the four roles and includes the following steps: (A) The client requests authorization from the resource owner.  

+--------------------------------------++.|A-----------+|授权请求->|资源|||_资源|||||_所有者|||||所有者|||所有者|||B--------------------------------------------------------++++..------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----访问令牌-----|||||+---------------------------------------------------------------------------------------------------------------------------+|||||||+---------------------+||--(E)-----------------------------------------------------------------------------------------------------------------------------------------------------+|----------------------------------------------------------------------------------------------------------------------------------------------并且包括以下步骤：（a）客户端请求来自资源所有者的授权。  

>[en]The authorization request can be made directly to the resource owner (as shown), or preferably indirectly via the authorization server as an intermediary.  

授权请求可以直接向资源所有者（如图所示）提出，或者优选地通过作为中介的授权服务器间接提出。  

>[en](B) The client receives an authorization grant, which is a credential representing the resource owner's authorization, expressed using one of four grant types defined in this specification or using an extension grant type.  

(B)客户端接收授权授权授权，该授权授权授权是表示资源所有者的授权的凭证，使用本规范中定义的四种授权类型之一或使用扩展授权类型来表示。  

>[en]The authorization grant type depends on the method used by the client to request authorization and the types supported by the authorization server.  

授权授予类型取决于客户端用于请求授权的方法和授权服务器支持的类型。  

>[en](C) The client requests an access token by authenticating with the authorization server and presenting the authorization grant.  

（c）客户端通过与授权服务器进行认证并呈现授权授权请求访问令牌。  

>[en](D) The authorization server authenticates the client and validates the authorization grant, and if valid, issues an access token.  

（d）授权服务器验证客户端并验证授权授权，并且如果有效，则发出访问令牌。  

>[en]Hardt Standards Track [Page 7] RFC 6749 OAuth 2.0 October 2012 (E) The client requests the protected resource from the resource server and authenticates by presenting the access token.  

硬标准跟踪[第7页]RFC 6749 OAuth 2012年10月2.0 (E)客户端向资源服务器请求受保护的资源，并通过呈现访问令牌进行身份验证。  

>[en](F) The resource server validates the access token, and if valid, serves the request.  

（f）资源服务器验证访问令牌，并且如果有效，则服务请求。  

>[en]The preferred method for the client to obtain an authorization grant from the resource owner (depicted in steps (A) and (B)) is to use the authorization server as an intermediary, which is illustrated in Figure 3 in Section 4.1.  

客户机从资源所有者（在步骤(A)和(B)中描述）获得授权授权授权的优选方法是使用授权服务器作为中介，这在第4.1节的图3中说明。  




## 1.3. Authorization Grant  
>[en]An authorization grant is a credential representing the resource owner's authorization (to access its protected resources) used by the client to obtain an access token.  

授权授权是表示客户端用于获得访问令牌的资源所有者的授权（访问其受保护的资源）的凭证。  

>[en]This specification defines four grant types -- authorization code, implicit, resource owner password credentials, and client credentials -- as well as an extensibility mechanism for defining additional types.  

该规范定义了四种授权类型——授权代码、隐式、资源所有者密码凭证和客户端凭证——以及用于定义其他类型的可扩展性机制。  




### 1.3.1. Authorization Code  
>[en]The authorization code is obtained by using an authorization server as an intermediary between the client and resource owner.  

授权代码是通过使用授权服务器作为客户端和资源所有者之间的中介来获得的。  

>[en]Instead of requesting authorization directly from the resource owner, the client directs the resource owner to an authorization server (via its user-agent as defined in [RFC2616]), which in turn directs the resource owner back to the client with the authorization code.  

客户端没有直接向资源所有者请求授权，而是将资源所有者定向到授权服务器（通过[RFC2616]中定义的其用户代理），授权服务器反过来将资源所有者定向回具有授权代码的客户端。  

>[en]Before directing the resource owner back to the client with the authorization code, the authorization server authenticates the resource owner and obtains authorization.  

在用授权代码将资源所有者引导回客户端之前，授权服务器对资源所有者进行身份验证并获得授权。  

>[en]Because the resource owner only authenticates with the authorization server, the resource owner's credentials are never shared with the client.  

因为资源所有者仅使用授权服务器进行身份验证，所以资源所有者的凭据永远不会与客户端共享。  

>[en]The authorization code provides a few important security benefits, such as the ability to authenticate the client, as well as the transmission of the access token directly to the client without passing it through the resource owner's user-agent and potentially exposing it to others, including the resource owner.  

授权代码提供了一些重要的安全好处，例如对客户端进行身份验证的能力，以及直接将访问令牌传输到客户端而不通过资源所有者的用户代理并将其暴露给其他人，包括资源所有者。  




### 1.3.2. Implicit  
>[en]The implicit grant is a simplified authorization code flow optimized for clients implemented in a browser using a scripting language such as JavaScript.  

隐式授权是一种简化的授权代码流，它针对使用JavaScript等脚本语言在浏览器中实现的客户端进行了优化。  

>[en]In the implicit flow, instead of issuing the client an authorization code, the client is issued an access token directly Hardt Standards Track [Page 8] RFC 6749 OAuth 2.0 October 2012 (as the result of the resource owner authorization).  

在隐式流程中，不是向客户端发出授权码，而是直接向客户端发出访问令牌，硬标准跟踪[第8页]RFC 6749 OAuth 2.0 2012年10月2日(作为资源所有者授权的结果)。  

>[en]The grant type is implicit, as no intermediate credentials (such as an authorization code) are issued (and later used to obtain an access token).  

授予类型是隐式的，因为没有发布中间凭据（例如授权代码）（稍后用于获取访问令牌）。  

>[en]When issuing an access token during the implicit grant flow, the authorization server does not authenticate the client.  

当在隐式授权流期间发布访问令牌时，授权服务器不验证客户端。  

>[en]In some cases, the client identity can be verified via the redirection URI used to deliver the access token to the client.  

在某些情况下，客户端标识可以通过用于向客户端传递访问令牌的重定向URI来验证。  

>[en]The access token may be exposed to the resource owner or other applications with access to the resource owner's user-agent.  

访问令牌可以暴露给资源所有者或其他访问资源所有者的用户代理的应用程序。  

>[en]Implicit grants improve the responsiveness and efficiency of some clients (such as a client implemented as an in-browser application), since it reduces the number of round trips required to obtain an access token.  

隐式授权提高了一些客户端（例如实现为浏览器内应用程序的客户端）的响应性和效率，因为它减少了获得访问令牌所需的往返次数。  

>[en]However, this convenience should be weighed against the security implications of using implicit grants, such as those described in Sections 10.3 and 10.16, especially when the authorization code grant type is available.  

然而，这种便利性应当与使用隐式授权（如第10.3和10.16节中描述的那些）的安全影响进行权衡，尤其是在授权代码授权类型可用时。  




### 1.3.3. Resource Owner Password Credentials  
>[en]The resource owner password credentials (i.e., username and password) can be used directly as an authorization grant to obtain an access token.  

资源所有者密码凭据（即，用户名和密码）可以直接用作获得访问令牌的授权授权授权。  

>[en]The credentials should only be used when there is a high degree of trust between the resource owner and the client (e.g., the client is part of the device operating system or a highly privileged application), and when other authorization grant types are not available (such as an authorization code).  

只有当资源所有者和客户端之间具有高度信任时（例如，客户端是设备操作系统或高度特权应用程序的一部分），以及当其他授权授予类型不可用时（例如授权代码），才应该使用凭证。  

>[en]Even though this grant type requires direct client access to the resource owner credentials, the resource owner credentials are used for a single request and are exchanged for an access token.  

尽管这种授权类型要求客户端直接访问资源所有者凭证，但是资源所有者凭证用于单个请求，并为访问令牌交换。  

>[en]This grant type can eliminate the need for the client to store the resource owner credentials for future use, by exchanging the credentials with a long-lived access token or refresh token.  

这种授权类型可以通过与长期访问令牌或刷新令牌交换凭证，消除客户端存储资源所有者凭证以供将来使用的需要。  




### 1.3.4. Client Credentials  
>[en]The client credentials (or other forms of client authentication) can be used as an authorization grant when the authorization scope is limited to the protected resources under the control of the client, or to protected resources previously arranged with the authorization server.  

当授权范围限于客户端控制下的受保护资源或先前与授权服务器安排的受保护资源时，客户端凭证(或其他形式的客户端认证)可以用作授权授权授权。  

>[en]Client credentials are used as an authorization grant typically when the client is acting on its own behalf (the client is also the resource owner) or is requesting access to protected resources based on an authorization previously arranged with the authorization server.  

客户端凭证通常用作授权授权授权，当客户端代表其自身（客户端也是资源所有者）进行操作或基于先前与授权服务器安排的授权请求访问受保护资源时。  




## 1.4. Access Token  
>[en]Access tokens are credentials used to access protected resources.  

访问令牌是用于访问受保护资源的凭据。  

>[en]An access token is a string representing an authorization issued to the client.  

访问令牌是表示向客户端发出的授权的字符串。  

>[en]The string is usually opaque to the client.  

字符串通常对客户端不透明。  

>[en]Tokens represent specific scopes and durations of access, granted by the resource owner, and enforced by the resource server and authorization server.  

令牌表示由资源所有者授予并由资源服务器和授权服务器强制的特定访问范围和持续时间。  

>[en]The token may denote an identifier used to retrieve the authorization information or may self-contain the authorization information in a verifiable manner (i.e., a token string consisting of some data and a signature).  

令牌可以表示用于检索授权信息的标识符，或者可以以可验证的方式(即，由某些数据和签名组成的令牌字符串)自包含授权信息。  

>[en]Additional authentication credentials, which are beyond the scope of this specification, may be required in order for the client to use a token.  

为了让客户端使用令牌，可能需要额外的身份验证凭据，这些凭据超出了本规范的范围。  

>[en]The access token provides an abstraction layer, replacing different authorization constructs (e.g., username and password) with a single token understood by the resource server.  

访问令牌提供一个抽象层，用资源服务器理解的单个令牌替换不同的授权结构（例如，用户名和密码）。  

>[en]This abstraction enables issuing access tokens more restrictive than the authorization grant used to obtain them, as well as removing the resource server's need to understand a wide range of authentication methods.  

这种抽象使得能够发布比用于获取访问令牌的授权授权授权更具限制性的访问令牌，并且消除了资源服务器理解各种身份验证方法的需要。  

>[en]Access tokens can have different formats, structures, and methods of utilization (e.g., cryptographic properties) based on the resource server security requirements.  

访问令牌可以具有基于资源服务器安全需求的不同格式、结构和使用方法（例如，密码属性）。  

>[en]Access token attributes and the methods used to access protected resources are beyond the scope of this specification and are defined by companion specifications such as [RFC6750].  

访问令牌属性和用于访问受保护资源的方法超出了本规范的范围，并由诸如[RCFC5050]的伙伴规范定义。  




## 1.5. Refresh Token  
>[en]Refresh tokens are credentials used to obtain access tokens.  

刷新令牌是用于获取访问令牌的凭据。  

>[en]Refresh tokens are issued to the client by the authorization server and are used to obtain a new access token when the current access token becomes invalid or expires, or to obtain additional access tokens with identical or narrower scope (access tokens may have a shorter lifetime and fewer permissions than authorized by the resource owner).  

刷新令牌由授权服务器颁发给客户端，用于在当前访问令牌无效或过期时获得新的访问令牌，或者获得具有相同或更窄范围的附加访问令牌（访问令牌可能具有更短的生存期和更少的许可）。比资源所有者授权的离子）。  

>[en]Issuing a refresh token is optional at the discretion of the authorization server.  

在授权服务器的权限下，可选地发布刷新令牌。  

>[en]If the authorization server issues a refresh token, it is included when issuing an access token (i.e., step (D) in Figure 1).  

如果授权服务器发出刷新令牌，则在发布访问令牌时（包括图1中的步骤（d））包含刷新令牌。  

>[en]A refresh token is a string representing the authorization granted to the client by the resource owner.  

刷新令牌是表示资源所有者授予客户端的授权的字符串。  

>[en]The string is usually opaque to the client.  

字符串通常对客户端不透明。  

>[en]The token denotes an identifier used to retrieve the Hardt Standards Track [Page 10] RFC 6749 OAuth 2.0 October 2012 authorization information.  

令牌表示用于检索硬标准轨道[第10页]RFC 6749OAuth 2012年10月2.0授权信息的标识符。  

>[en]Unlike access tokens, refresh tokens are intended for use only with authorization servers and are never sent to resource servers.  

不同于访问令牌，刷新令牌仅用于授权服务器，并且从不发送到资源服务器。  

>[en]+--------+ +---------------+ | |--(A)------- Authorization Grant --------->| | | | | | | |<-(B)----------- Access Token -------------| | | | & Refresh Token | | | | | | | | +----------+ | | | |--(C)---- Access Token ---->| | | | | | | | | | | |<-(D)- Protected Resource --| Resource | | Authorization | | Client | | Server | | Server | | |--(E)---- Access Token ---->| | | | | | | | | | | |<-(F)- Invalid Token Error -| | | | | | +----------+ | | | | | | | |--(G)----------- Refresh Token ----------->| | | | | | | |<-(H)----------- Access Token -------------| | +--------+ & Optional Refresh Token +---------------+ Figure 2: Refreshing an Expired Access Token The flow illustrated in Figure 2 includes the following steps: (A) The client requests an access token by authenticating with the authorization server and presenting an authorization grant.  

+--------------------------------------------------------------------------------------------------------------------------------------------------------++||||_.||||||||||||||||||||||||||.------------------------------------------------------------------------------------------------------------------------------------||||<-(D)-受保护资源--|资源||授权||客户端|||服务器|||服务器|||服务器|||-------------------------访问令牌------>||||||||||||||||||_||客户|||服务器||服务器||服务器||服务器|服务器||服务器||服务器||服务器||||_服务器||||||_服务器||||__服务器|||||_服务器|||||||_服务器||||_||_||||||||||||||_|||||||||||__|<-(H)----------------------------------------------------------------|--------------------------------------------------------------------------------------------------------+-----------------+图2：刷新过期访问令牌图2所示的流程包括以下步骤：(A)客户端通过与授权服务器进行身份验证并呈现授权授予来请求访问令牌。  

>[en](B) The authorization server authenticates the client and validates the authorization grant, and if valid, issues an access token and a refresh token.  

(B)授权服务器对客户端进行身份验证并验证授权授权，如果有效，则发出访问令牌和刷新令牌。  

>[en](C) The client makes a protected resource request to the resource server by presenting the access token.  

（c）客户端通过呈现访问令牌向资源服务器发出受保护的资源请求。  

>[en](D) The resource server validates the access token, and if valid, serves the request.  

（d）资源服务器验证访问令牌，并且如果有效，则服务请求。  

>[en](E) Steps (C) and (D) repeat until the access token expires.  

（e）重复步骤（c）和（d），直到访问令牌到期。  

>[en]If the client knows the access token expired, it skips to step (G); otherwise, it makes another protected resource request.  

如果客户端知道访问令牌过期，则跳过步骤（G）；否则，它将生成另一个受保护的资源请求。  

>[en](F) Since the access token is invalid, the resource server returns an invalid token error.  

（f）由于访问令牌无效，资源服务器返回无效令牌错误。  

>[en]Hardt Standards Track [Page 11] RFC 6749 OAuth 2.0 October 2012 (G) The client requests a new access token by authenticating with the authorization server and presenting the refresh token.  

硬标准跟踪[第11页]RFC 6749 OAuth 2.0 2012年10月(G)客户端通过与授权服务器进行身份验证并呈现刷新令牌来请求新的访问令牌。  

>[en]The client authentication requirements are based on the client type and on the authorization server policies.  

客户端认证要求是基于客户端类型和授权服务器策略的。  

>[en](H) The authorization server authenticates the client and validates the refresh token, and if valid, issues a new access token (and, optionally, a new refresh token).  

(H)授权服务器对客户端进行身份验证并验证刷新令牌，如果有效，则发出新的访问令牌(以及可选地，发出新的刷新令牌)。  

>[en]Steps (C), (D), (E), and (F) are outside the scope of this specification, as described in Section 7.  

步骤（c）、（d）、（e）和（f）超出了本规范的范围，如第7节所述。  




## 1.6. TLS Version  
>[en]Whenever Transport Layer Security (TLS) is used by this specification, the appropriate version (or versions) of TLS will vary over time, based on the widespread deployment and known security vulnerabilities.  

每当此规范使用传输层安全性（TLS）时，TLS的适当版本（或版本）将根据广泛部署和已知的安全漏洞随时间而变化。  

>[en]At the time of this writing, TLS version 1.2 [RFC5246] is the most recent version, but has a very limited deployment base and might not be readily available for implementation.  

在撰写本文时，TLS版本1.2[RFC5246]是最新版本，但是部署基础非常有限，可能不容易实现。  

>[en]TLS version 1.0 [RFC2246] is the most widely deployed version and will provide the broadest interoperability.  

TLS版本1 [RCF2246]是最广泛部署的版本，并将提供最广泛的互操作性。  

>[en]Implementations MAY also support additional transport-layer security mechanisms that meet their security requirements.  

实现还可以支持满足其安全要求的附加传输层安全机制。  




## 1.7. HTTP Redirections  
>[en]This specification makes extensive use of HTTP redirections, in which the client or the authorization server directs the resource owner's user-agent to another destination.  

此规范广泛使用HTTP重定向，其中客户端或授权服务器将资源所有者的用户代理定向到另一个目的地。  

>[en]While the examples in this specification show the use of the HTTP 302 status code, any other method available via the user-agent to accomplish this redirection is allowed and is considered to be an implementation detail.  

虽然本规范中的示例显示了HTTP 302状态代码的使用，但是允许通过用户代理可用的任何其他方法来完成此重定向，并且被认为是实现细节。  




## 1.8. Interoperability  
>[en]OAuth 2.0 provides a rich authorization framework with well-defined security properties.  

OAuth2提供了具有良好定义的安全属性的丰富授权框架。  

>[en]However, as a rich and highly extensible framework with many optional components, on its own, this specification is likely to produce a wide range of non-interoperable implementations.  

然而，作为具有许多可选组件的丰富和高度可扩展的框架，该规范本身可能产生大量不可互操作的实现。  

>[en]In addition, this specification leaves a few required components partially or fully undefined (e.g., client registration, authorization server capabilities, endpoint discovery).  

此外，该规范还保留了一些部分或全部未定义的必需组件（例如，客户端注册、授权服务器功能、端点发现）。  

>[en]Without Hardt Standards Track [Page 12] RFC 6749 OAuth 2.0 October 2012 these components, clients must be manually and specifically configured against a specific authorization server and resource server in order to interoperate.  

如果没有Hardt Standards Track[Page 12]RFC 6749 OAuth 2.0 2012年10月2.0，这些组件必须针对特定的授权服务器和资源服务器手动和特定地配置客户端，以便进行互操作。  

>[en]This framework was designed with the clear expectation that future work will define prescriptive profiles and extensions necessary to achieve full web-scale interoperability.  

该框架在设计时明确地预期，未来的工作将定义实现完全网络级互操作性所必需的规范性配置文件和扩展。  




## 1.9. Notational Conventions  
>[en]The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this specification are to be interpreted as described in [RFC2119].  

本说明书中的关键词“必须”、“必须不要”、“要求”、“应当”、“不应”、“应当”、“不应”、“建议”、“可能”和“可选”应解释为[RFC2119]中所述。  

>[en]This specification uses the Augmented Backus-Naur Form (ABNF) notation of [RFC5234].  

本规范使用[RCF5244]的增强Backus Naur Form（ABNF）表示法。  

>[en]Additionally, the rule URI-reference is included from "Uniform Resource Identifier (URI): Generic Syntax" [RFC3986].  

此外，规则URI引用包含在“统一资源标识符（URI）：泛型语法”[RFC986]中。  

>[en]Certain security-related terms are to be understood in the sense defined in [RFC4949].  

某些安全相关术语将在[RCFC449 ]中定义的意义上理解。  

>[en]These terms include, but are not limited to, "attack", "authentication", "authorization", "certificate", "confidentiality", "credential", "encryption", "identity", "sign", "signature", "trust", "validate", and "verify".  

这些术语包括但不限于“攻击”、“认证”、“授权”、“证书”、“机密性”、“凭证”、“加密”、“身份”、“签名”、“签名”、“信任”、“验证”和“验证”。  

>[en]Unless otherwise noted, all the protocol parameter names and values are case sensitive.  

除非另有说明，所有协议参数名称和值都区分大小写。  




# 2. Client Registration  
>[en]Before initiating the protocol, the client registers with the authorization server.  

在发起协议之前，客户端向授权服务器注册。  

>[en]The means through which the client registers with the authorization server are beyond the scope of this specification but typically involve end-user interaction with an HTML registration form.  

客户端向授权服务器注册的手段超出了本规范的范围，但通常涉及与HTML注册表单的最终用户交互。  

>[en]Client registration does not require a direct interaction between the client and the authorization server.  

客户端注册不需要客户端和授权服务器之间的直接交互。  

>[en]When supported by the authorization server, registration can rely on other means for establishing trust and obtaining the required client properties (e.g., redirection URI, client type).  

当授权服务器支持时，注册可以依靠其他方式来建立信任并获得所需的客户端属性（例如，重定向URI、客户端类型）。  

>[en]For example, registration can be accomplished using a self-issued or third-party-issued assertion, or by the authorization server performing client discovery using a trusted channel.  

例如，注册可以使用自发布或第三方发出的断言，或者由授权服务器使用可信信道执行客户端发现来完成。  

>[en]Hardt Standards Track [Page 13] RFC 6749 OAuth 2.0 October 2012 When registering a client, the client developer SHALL: o specify the client type as described in Section 2.1, o provide its client redirection URIs as described in Section 3.1.2, and o include any other information required by the authorization server (e.g., application name, website, description, logo image, the acceptance of legal terms).  

硬标准跟踪[第13页]RFC 6749 OAuth 2.0 2012年10月2.0在注册客户端时，客户端开发人员SHALL:o指定第2.1节中描述的客户端类型，o提供第3.1.2节中描述的客户端重定向URI，o包括auth所需的任何其他信息ORIZE服务器（例如应用程序名称、网站、描述、标识图像、法律条款的接受）。  




## 2.1. Client Types  
>[en]OAuth defines two client types, based on their ability to authenticate securely with the authorization server (i.e., ability to maintain the confidentiality of their client credentials): confidential Clients capable of maintaining the confidentiality of their credentials (e.g., client implemented on a secure server with restricted access to the client credentials), or capable of secure client authentication using other means.  

OAuth基于它们与授权服务器安全地进行身份验证的能力（即，维护其客户端凭证的机密性的能力）定义了两种客户端类型：能够维护其凭证的机密性的机密客户端（例如，实现n具有对客户端凭证的限制访问的安全服务器，或能够使用其他手段进行安全客户端认证。  

>[en]public Clients incapable of maintaining the confidentiality of their credentials (e.g., clients executing on the device used by the resource owner, such as an installed native application or a web browser-based application), and incapable of secure client authentication via any other means.  

公共客户端不能维护其凭证的机密性(例如，在资源所有者使用的设备上执行的客户端，例如安装的本地应用程序或基于web浏览器的应用程序)，并且不能通过任何其他手段进行安全客户端身份验证。  

>[en]The client type designation is based on the authorization server's definition of secure authentication and its acceptable exposure levels of client credentials.  

客户端类型指定基于授权服务器的安全身份验证定义及其可接受的客户端凭证的公开级别。  

>[en]The authorization server SHOULD NOT make assumptions about the client type.  

授权服务器不应对客户端类型进行假设。  

>[en]A client may be implemented as a distributed set of components, each with a different client type and security context (e.g., a distributed client with both a confidential server-based component and a public browser-based component).  

客户端可以被实现为分布式组件集合，每个组件具有不同的客户端类型和安全上下文（例如，具有基于机密服务器的组件和基于公共浏览器的组件的分布式客户端）。  

>[en]If the authorization server does not provide support for such clients or does not provide guidance with regard to their registration, the client SHOULD register each component as a separate client.  

如果授权服务器不为这些客户端提供支持或者不提供关于其注册的指导，则客户端应该将每个组件注册为单独的客户端。  

>[en]Hardt Standards Track [Page 14] RFC 6749 OAuth 2.0 October 2012 This specification has been designed around the following client profiles: web application A web application is a confidential client running on a web server.  

硬标准跟踪[第14页]RFC 6749 OAuth 2.0 2012年10月2日本规范围绕以下客户端配置文件设计：Web应用程序是运行在Web服务器上的机密客户端。  

>[en]Resource owners access the client via an HTML user interface rendered in a user-agent on the device used by the resource owner.  

资源所有者通过在资源所有者使用的设备上的用户代理中呈现的HTML用户界面访问客户端。  

>[en]The client credentials as well as any access token issued to the client are stored on the web server and are not exposed to or accessible by the resource owner.  

客户端凭证以及发给客户端的任何访问令牌都存储在Web服务器上，并且不向资源所有者公开或由资源所有者访问。  

>[en]user-agent-based application A user-agent-based application is a public client in which the client code is downloaded from a web server and executes within a user-agent (e.g., web browser) on the device used by the resource owner.  

基于用户代理的应用基于用户代理的应用程序是基于用户代理的应用程序是公共客户端，其中客户端代码从web服务器下载并在用户代理(例如，web浏览器)内对资源所有者使用的设备执行。  

>[en]Protocol data and credentials are easily accessible (and often visible) to the resource owner.  

协议数据和凭据很容易访问（并且经常可见）给资源所有者。  

>[en]Since such applications reside within the user-agent, they can make seamless use of the user-agent capabilities when requesting authorization.  

由于此类应用程序驻留在用户代理中，因此它们在请求授权时可以无缝地使用用户代理功能。  

>[en]native application A native application is a public client installed and executed on the device used by the resource owner.  

本机应用程序是在资源所有者使用的设备上安装并执行的公共客户端。  

>[en]Protocol data and credentials are accessible to the resource owner.  

资源所有者可以访问协议数据和凭据。  

>[en]It is assumed that any client authentication credentials included in the application can be extracted.  

假设可以提取包含在应用程序中的任何客户端认证凭据。  

>[en]On the other hand, dynamically issued credentials such as access tokens or refresh tokens can receive an acceptable level of protection.  

另一方面，动态发布的凭据（如访问令牌或刷新令牌）可以接收可接受的保护级别。  

>[en]At a minimum, these credentials are protected from hostile servers with which the application may interact.  

至少，这些凭据被保护与应用程序可以交互的敌对服务器保护。  

>[en]On some platforms, these credentials might be protected from other applications residing on the same device.  

在一些平台上，这些凭据可能被保护与驻留在同一设备上的其他应用程序无关。  




## 2.2. Client Identifier  
>[en]The authorization server issues the registered client a client identifier -- a unique string representing the registration information provided by the client.  

授权服务器向注册的客户端发出一个客户机标识符——表示客户机提供的注册信息的唯一字符串。  

>[en]The client identifier is not a secret; it is exposed to the resource owner and MUST NOT be used alone for client authentication.  

客户端标识符不是秘密；它暴露于资源所有者，不能单独用于客户端身份验证。  

>[en]The client identifier is unique to the authorization server.  

客户端标识符对于授权服务器是唯一的。  

>[en]The client identifier string size is left undefined by this specification.  

客户端标识符字符串大小由该规范未定义。  

>[en]The client should avoid making assumptions about the identifier size.  

客户端应该避免对标识符大小做出假设。  

>[en]The authorization server SHOULD document the size of any identifier it issues.  

授权服务器应该记录它所发出的任何标识符的大小。  




## 2.3. Client Authentication  
>[en]If the client type is confidential, the client and authorization server establish a client authentication method suitable for the security requirements of the authorization server.  

如果客户端类型是机密的，则客户端和授权服务器建立适合于授权服务器的安全要求的客户端认证方法。  

>[en]The authorization server MAY accept any form of client authentication meeting its security requirements.  

授权服务器可以接受满足其安全要求的任何形式的客户端认证。  

>[en]Confidential clients are typically issued (or establish) a set of client credentials used for authenticating with the authorization server (e.g., password, public/private key pair).  

机密客户端通常发布（或建立）一组客户端凭据，用于与授权服务器进行身份验证（例如，密码、公钥/私钥对）。  

>[en]The authorization server MAY establish a client authentication method with public clients.  

授权服务器可以建立与公共客户端的客户端认证方法。  

>[en]However, the authorization server MUST NOT rely on public client authentication for the purpose of identifying the client.  

但是，授权服务器不能为了识别客户端而依赖公共客户端身份验证。  

>[en]The client MUST NOT use more than one authentication method in each request.  

客户端不能在每个请求中使用多个身份验证方法。  




### 2.3.1. Client Password  
>[en]Clients in possession of a client password MAY use the HTTP Basic authentication scheme as defined in [RFC2617] to authenticate with the authorization server.  

拥有客户端密码的客户端可以使用[RFC2617]中定义的HTTP基本身份验证方案来与授权服务器进行身份验证。  

>[en]The client identifier is encoded using the "application/x-www-form-urlencoded" encoding algorithm per Appendix B, and the encoded value is used as the username; the client password is encoded using the same algorithm and used as the password.  

客户端标识符使用每个附录B的“application/x-www-form-urlencoded”编码算法进行编码，并且编码值用作用户名；客户端密码使用相同的算法进行编码并且用作密码。  

>[en]The authorization server MUST support the HTTP Basic authentication scheme for authenticating clients that were issued a client password.  

授权服务器必须支持HTTP Basic身份验证方案，用于对发出客户机密码的客户机进行身份验证。  

>[en]For example (with extra line breaks for display purposes only): Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3 Alternatively, the authorization server MAY support including the client credentials in the request-body using the following parameters: client_id REQUIRED.  

例如（仅用于显示目的的额外换行）：Authorization：Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3或者，授权服务器可能支持使用以下参数在请求主体中包括客户端凭据：client_id REQUIRED。  

>[en]The client identifier issued to the client during the registration process described by Section 2.2.  

在第2.2节描述的注册过程中向客户端发出的客户端标识符。  

>[en]client_secret REQUIRED.  

客户需要保密。  

>[en]The client secret.  

客户机密。  

>[en]The client MAY omit the parameter if the client secret is an empty string.  

如果客户端秘密是空字符串，则客户端可以省略参数。  

>[en]Hardt Standards Track [Page 16] RFC 6749 OAuth 2.0 October 2012 Including the client credentials in the request-body using the two parameters is NOT RECOMMENDED and SHOULD be limited to clients unable to directly utilize the HTTP Basic authentication scheme (or other password-based HTTP authentication schemes).  

硬标准跟踪[第16页]RFC 6749 OAuth 2.0 2012年10月2日离子方案）。  

>[en]The parameters can only be transmitted in the request-body and MUST NOT be included in the request URI.  

这些参数只能在请求体中传输，并且不能包含在请求URI中。  

>[en]For example, a request to refresh an access token (Section 6) using the body parameters (with extra line breaks for display purposes only): POST /token HTTP/1.1 Host: server.example.com Content-Type: application/x-www-form-urlencoded grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA &client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw The authorization server MUST require the use of TLS as described in Section 1.6 when sending requests using password authentication.  

例如，使用主体参数刷新访问令牌的请求（第6节）：POST/令牌HTTP/1.1主机：server.example.com Content-Type：application/x-www-form-urlencoded grant_type=.esh_token&.esh_token=tGzv3JOkF0XG5Qx2TlKWIA&client_id=s6BhdRkqt3&client_.=7Fjfp0ZBr1KtDRbnfVdmIw授权服务器在使用口令身份验证发送请求时必须使用第1.6节所述的TLS。  

>[en]Since this client authentication method involves a password, the authorization server MUST protect any endpoint utilizing it against brute force attacks.  

由于此客户端身份验证方法涉及密码，因此授权服务器必须保护使用它的任何端点免受暴力攻击。  




### 2.3.2. Other Authentication Methods  
>[en]The authorization server MAY support any suitable HTTP authentication scheme matching its security requirements.  

授权服务器可以支持与其安全性要求相匹配的任何合适的HTTP认证方案。  

>[en]When using other authentication methods, the authorization server MUST define a mapping between the client identifier (registration record) and authentication scheme.  

当使用其他身份验证方法时，授权服务器必须定义客户端标识符（注册记录）和身份验证方案之间的映射。  




## 2.4. Unregistered Clients  
>[en]This specification does not exclude the use of unregistered clients.  

本规范不排除未注册客户端的使用。  

>[en]However, the use of such clients is beyond the scope of this specification and requires additional security analysis and review of its interoperability impact.  

然而，这种客户端的使用超出了本规范的范围，需要额外的安全性分析和对其互操作性影响的审查。  




# 3. Protocol Endpoints  
>[en]The authorization process utilizes two authorization server endpoints (HTTP resources): o Authorization endpoint - used by the client to obtain authorization from the resource owner via user-agent redirection.  

授权过程使用两个授权服务器端点（HTTP资源）：o授权端点——客户端使用该端点通过用户-代理重定向从资源所有者获得授权。  

>[en]o Token endpoint - used by the client to exchange an authorization grant for an access token, typically with client authentication.  

o令牌端点-客户端用于交换访问令牌的授权授权授权，通常使用客户端身份验证。  

>[en]As well as one client endpoint: o Redirection endpoint - used by the authorization server to return responses containing authorization credentials to the client via the resource owner user-agent.  

以及一个客户端端点：o Redirection端点——授权服务器使用该端点通过资源所有者用户代理向客户端返回包含授权凭证的响应。  

>[en]Not every authorization grant type utilizes both endpoints.  

并非每个授权授予类型都使用端点。  

>[en]Extension grant types MAY define additional endpoints as needed.  

扩展授权类型可以根据需要定义附加端点。  




## 3.1. Authorization Endpoint  
>[en]The authorization endpoint is used to interact with the resource owner and obtain an authorization grant.  

授权端点用于与资源所有者交互并获得授权授权。  

>[en]The authorization server MUST first verify the identity of the resource owner.  

授权服务器必须首先验证资源所有者的身份。  

>[en]The way in which the authorization server authenticates the resource owner (e.g., username and password login, session cookies) is beyond the scope of this specification.  

授权服务器验证资源所有者（例如，用户名和密码登录、会话cookie）的方式超出了本规范的范围。  

>[en]The means through which the client obtains the location of the authorization endpoint are beyond the scope of this specification, but the location is typically provided in the service documentation.  

客户机获取授权端点的位置的方法超出了本规范的范围，但是该位置通常在服务文档中提供。  

>[en]The endpoint URI MAY include an "application/x-www-form-urlencoded" formatted (per Appendix B) query component ([RFC3986] Section 3.4), which MUST be retained when adding additional query parameters.  

端点URI可能包括“application/x-www-form-urlencoded”（每个附录B）格式化的查询组件（[RFC3986]部分3.4），在添加其他查询参数时必须保留该组件。  

>[en]The endpoint URI MUST NOT include a fragment component.  

端点URI不能包含片段组件。  

>[en]Since requests to the authorization endpoint result in user authentication and the transmission of clear-text credentials (in the HTTP response), the authorization server MUST require the use of TLS as described in Section 1.6 when sending requests to the authorization endpoint.  

由于对授权端点的请求导致用户身份验证和清楚文本凭据的传输（在HTTP响应中），所以授权服务器必须在向授权端点发送请求时要求使用第1.6节所述的TLS。  

>[en]The authorization server MUST support the use of the HTTP "GET" method [RFC2616] for the authorization endpoint and MAY support the use of the "POST" method as well.  

授权服务器必须支持对授权端点使用HTTP“GET”方法[RFC2616]，并且MAY还支持“POST”方法的使用。  

>[en]Hardt Standards Track [Page 18] RFC 6749 OAuth 2.0 October 2012 Parameters sent without a value MUST be treated as if they were omitted from the request.  

硬标准轨道[第18页]RFC 6749 OAuth 2.0 2012年10月2日发送的参数没有值必须被当作从请求中省略的参数对待。  

>[en]The authorization server MUST ignore unrecognized request parameters.  

授权服务器必须忽略未识别的请求参数。  

>[en]Request and response parameters MUST NOT be included more than once.  

请求和响应参数不能超过一次。  




### 3.1.1. Response Type  
>[en]The authorization endpoint is used by the authorization code grant type and implicit grant type flows.  

授权端点由授权代码授予类型和隐式授予类型流使用。  

>[en]The client informs the authorization server of the desired grant type using the following parameter: response_type REQUIRED.  

客户端使用以下参数向授权服务器通知所需的授予类型：所需的响应类型。  

>[en]The value MUST be one of "code" for requesting an authorization code as described by Section 4.1.1, "token" for requesting an access token (implicit grant) as described by Section 4.2.1, or a registered extension value as described by Section 8.4.  

该值必须是用于请求授权代码的“代码”之一，如第4.1.1节所述的“令牌”，用于请求如4.2.1节所描述的访问令牌（隐式授予），或如第8.4节所述的注册扩展值。  

>[en]Extension response types MAY contain a space-delimited (%x20) list of values, where the order of values does not matter (e.g., response type "a b" is the same as "b a").  

扩展响应类型MAY包含以空格分隔（%x20）的值列表，其中值的顺序无关紧要（例如，响应类型“a b”与“b a”相同）。  

>[en]The meaning of such composite response types is defined by their respective specifications.  

这种复合响应类型的含义是由它们各自的规范来定义的。  

>[en]If an authorization request is missing the "response_type" parameter, or if the response type is not understood, the authorization server MUST return an error response as described in Section 4.1.2.1.  

如果授权请求缺少“._type”参数，或者如果不理解响应类型，授权服务器必须返回错误响应，如4.1.2.1节所述。  




### 3.1.2. Redirection Endpoint  
>[en]After completing its interaction with the resource owner, the authorization server directs the resource owner's user-agent back to the client.  

在完成与资源所有者的交互之后，授权服务器将资源所有者的用户代理引导回客户端。  

>[en]The authorization server redirects the user-agent to the client's redirection endpoint previously established with the authorization server during the client registration process or when making the authorization request.  

授权服务器将用户代理重定向到客户端重定向端点，客户端重定向端点以前在客户端注册过程期间或在做出授权请求时与授权服务器一起建立。  

>[en]The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.  

重定向端点URI必须是由[RCFC986]第4.3节定义的绝对URI。  

>[en]The endpoint URI MAY include an "application/x-www-form-urlencoded" formatted (per Appendix B) query component ([RFC3986] Section 3.4), which MUST be retained when adding additional query parameters.  

端点URI可能包括“application/x-www-form-urlencoded”（每个附录B）格式化的查询组件（[RFC3986]部分3.4），在添加其他查询参数时必须保留该组件。  

>[en]The endpoint URI MUST NOT include a fragment component.  

端点URI不能包含片段组件。  




#### 3.1.2.1. Endpoint Request Confidentiality  
>[en]The redirection endpoint SHOULD require the use of TLS as described in Section 1.6 when the requested response type is "code" or "token", or when the redirection request will result in the transmission of sensitive credentials over an open network.  

当请求的响应类型是“代码”或“令牌”时，或者当重定向请求将导致敏感证书在开放网络上传输时，重定向端点应该要求使用第1.6节中所描述的TLS。  

>[en]This specification does not mandate the use of TLS because at the time of this writing, requiring clients to deploy TLS is a significant hurdle for many client developers.  

该规范并不强制使用TLS，因为在撰写本文时，要求客户机部署TLS是许多客户机开发人员的一个重大障碍。  

>[en]If TLS is not available, the authorization server SHOULD warn the resource owner about the insecure endpoint prior to redirection (e.g., display a message during the authorization request).  

如果TLS不可用，授权服务器应该在重定向之前警告资源所有者不安全的端点（例如，在授权请求期间显示消息）。  

>[en]Lack of transport-layer security can have a severe impact on the security of the client and the protected resources it is authorized to access.  

传输层安全性的缺乏可能对客户端及其授权访问的受保护资源的安全性产生严重影响。  

>[en]The use of transport-layer security is particularly critical when the authorization process is used as a form of delegated end-user authentication by the client (e.g., third-party sign-in service).  

当授权过程被用作委托端用户验证的形式（例如，第三方登录服务）时，传输层安全性的使用尤为关键。  




#### 3.1.2.2. Registration Requirements  
>[en]The authorization server MUST require the following clients to register their redirection endpoint: o Public clients.  

授权服务器必须要求下列客户端注册它们的重定向端点：O公共客户端。  

>[en]o Confidential clients utilizing the implicit grant type.  

使用隐式授予类型的机密客户。  

>[en]The authorization server SHOULD require all clients to register their redirection endpoint prior to utilizing the authorization endpoint.  

授权服务器应该要求所有客户端在使用授权端点之前注册它们的重定向端点。  

>[en]The authorization server SHOULD require the client to provide the complete redirection URI (the client MAY use the "state" request parameter to achieve per-request customization).  

授权服务器应该要求客户端提供完整的重定向URI（客户端可以使用“state”请求参数来实现每个请求的定制）。  

>[en]If requiring the registration of the complete redirection URI is not possible, the authorization server SHOULD require the registration of the URI scheme, authority, and path (allowing the client to dynamically vary only the query component of the redirection URI when requesting authorization).  

如果不可能要求注册完整的重定向URI，授权服务器应该要求注册URI方案、权限和路径（允许客户端在请求授权时仅动态地改变重定向URI的查询组件）。  

>[en]The authorization server MAY allow the client to register multiple redirection endpoints.  

授权服务器可以允许客户端注册多个重定向端点。  

>[en]Lack of a redirection URI registration requirement can enable an attacker to use the authorization endpoint as an open redirector as described in Section 10.15.  

缺少重定向URI注册要求可使攻击者能够使用授权端点作为开放重定向器，如第10.15节所述。  




#### 3.1.2.3. Dynamic Configuration  
>[en]If multiple redirection URIs have been registered, if only part of the redirection URI has been registered, or if no redirection URI has been registered, the client MUST include a redirection URI with the authorization request using the "redirect_uri" request parameter.  

如果已经注册了多个重定向URI，如果仅注册了部分重定向URI，或者如果没有注册重定向URI，则客户端必须使用“redirect_uri”请求参数在授权请求中包括重定向URI。  

>[en]When a redirection URI is included in an authorization request, the authorization server MUST compare and match the value received against at least one of the registered redirection URIs (or URI components) as defined in [RFC3986] Section 6, if any redirection URIs were registered.  

当在授权请求中包括重定向URI时，如果注册了任何重定向URI，则授权服务器必须将接收到的值与[RFC3986]第6节中定义的至少一个已注册重定向URI（或URI组件）进行比较和匹配。  

>[en]If the client registration included the full redirection URI, the authorization server MUST compare the two URIs using simple string comparison as defined in [RFC3986] Section 6.2.1.  

如果客户端注册包括完整的重定向URI，则授权服务器必须使用[RFC3986]第6.2.1节中定义的简单字符串比较来比较这两个URI。  




#### 3.1.2.4. Invalid Endpoint  
>[en]If an authorization request fails validation due to a missing, invalid, or mismatching redirection URI, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.  

如果授权请求由于缺少、无效或不匹配的重定向URI而验证失败，则授权服务器应将错误通知资源所有者，并且必须不自动将用户代理重定向到无效重定向URI。  




#### 3.1.2.5. Endpoint Content  
>[en]The redirection request to the client's endpoint typically results in an HTML document response, processed by the user-agent.  

对客户端端点的重定向请求通常导致由用户代理处理的HTML文档响应。  

>[en]If the HTML response is served directly as the result of the redirection request, any script included in the HTML document will execute with full access to the redirection URI and the credentials it contains.  

如果作为重定向请求的结果直接提供HTML响应，则HTML文档中包含的任何脚本都将在完全访问重定向URI及其包含的凭据的情况下执行。  

>[en]The client SHOULD NOT include any third-party scripts (e.g., third- party analytics, social plug-ins, ad networks) in the redirection endpoint response.  

客户端不应该在重定向端点响应中包括任何第三方脚本（例如，第三方分析、社交插件、广告网络）。  

>[en]Instead, it SHOULD extract the credentials from the URI and redirect the user-agent again to another endpoint without exposing the credentials (in the URI or elsewhere).  

相反，它应该从URI中提取凭据，并将用户代理再次重定向到另一个端点，而不公开凭据（在URI或其他地方）。  

>[en]If third-party scripts are included, the client MUST ensure that its own scripts (used to extract and remove the credentials from the URI) will execute first.  

如果包括第三方脚本，则客户端必须确保其自己的脚本（用于从URI中提取和删除凭据）将首先执行。  




## 3.2. Token Endpoint  
>[en]The token endpoint is used by the client to obtain an access token by presenting its authorization grant or refresh token.  

令牌端点被客户端用来通过呈现其授权授权或刷新令牌来获得访问令牌。  

>[en]The token endpoint is used with every authorization grant except for the implicit grant type (since an access token is issued directly).  

除了隐式授予类型（因为直接发出访问令牌），令牌端点与每个授权授予一起使用。  

>[en]Hardt Standards Track [Page 21] RFC 6749 OAuth 2.0 October 2012 The means through which the client obtains the location of the token endpoint are beyond the scope of this specification, but the location is typically provided in the service documentation.  

硬标准轨道[第21页]RFC 6749 OAuth 2.0 2012年10月2.0客户端通过它获得令牌端点的位置的方法超出了本规范的范围，但是位置通常在服务文档中提供。  

>[en]The endpoint URI MAY include an "application/x-www-form-urlencoded" formatted (per Appendix B) query component ([RFC3986] Section 3.4), which MUST be retained when adding additional query parameters.  

端点URI可能包括“application/x-www-form-urlencoded”（每个附录B）格式化的查询组件（[RFC3986]部分3.4），在添加其他查询参数时必须保留该组件。  

>[en]The endpoint URI MUST NOT include a fragment component.  

端点URI不能包含片段组件。  

>[en]Since requests to the token endpoint result in the transmission of clear-text credentials (in the HTTP request and response), the authorization server MUST require the use of TLS as described in Section 1.6 when sending requests to the token endpoint.  

由于对令牌端点的请求导致明文证书的传输（在HTTP请求和响应中），授权服务器在向令牌端点发送请求时必须要求使用第1.6节中所描述的TLS。  

>[en]The client MUST use the HTTP "POST" method when making access token requests.  

客户端在访问令牌请求时必须使用HTTP“POST”方法。  

>[en]Parameters sent without a value MUST be treated as if they were omitted from the request.  

无值发送的参数必须被处理，就像它们从请求中被省略一样。  

>[en]The authorization server MUST ignore unrecognized request parameters.  

授权服务器必须忽略未识别的请求参数。  

>[en]Request and response parameters MUST NOT be included more than once.  

请求和响应参数不能超过一次。  




### 3.2.1. Client Authentication  
>[en]Confidential clients or other clients issued client credentials MUST authenticate with the authorization server as described in Section 2.3 when making requests to the token endpoint.  

当向令牌端点发出请求时，机密客户机或其他发出客户机凭证的客户机必须使用授权服务器进行身份验证，如第2.3节所述。  

>[en]Client authentication is used for: o Enforcing the binding of refresh tokens and authorization codes to the client they were issued to.  

客户端身份验证用于：o强制将刷新令牌和授权代码绑定到发出给它们的客户端。  

>[en]Client authentication is critical when an authorization code is transmitted to the redirection endpoint over an insecure channel or when the redirection URI has not been registered in full.  

当授权代码通过不安全的通道传输到重定向端点时，或者当重定向URI没有完全注册时，客户端身份验证是关键的。  

>[en]o Recovering from a compromised client by disabling the client or changing its credentials, thus preventing an attacker from abusing stolen refresh tokens.  

o通过禁用客户端或更改其凭证从受损客户端恢复，从而防止攻击者滥用被窃取的刷新令牌。  

>[en]Changing a single set of client credentials is significantly faster than revoking an entire set of refresh tokens.  

更改单个客户端证书集比撤销整个刷新令牌组要快得多。  

>[en]o Implementing authentication management best practices, which require periodic credential rotation.  

o实现认证管理最佳实践，这需要定期凭证旋转。  

>[en]Rotation of an entire set of refresh tokens can be challenging, while rotation of a single set of client credentials is significantly easier.  

整个刷新令牌集合的旋转是具有挑战性的，而单组客户端证书的旋转更容易。  

>[en]Hardt Standards Track [Page 22] RFC 6749 OAuth 2.0 October 2012 A client MAY use the "client_id" request parameter to identify itself when sending requests to the token endpoint.  

硬标准跟踪[第22页]RFC 6749 OAuth 2.0 2012年10月2.0客户端可能在向令牌端点发送请求时使用“client_id”请求参数来标识自己。  

>[en]In the "authorization_code" "grant_type" request to the token endpoint, an unauthenticated client MUST send its "client_id" to prevent itself from inadvertently accepting a code intended for a client with a different "client_id".  

在对令牌端点的“authorization_code”“grant_type”请求中，未经身份验证的客户端必须发送其“client_id”，以防止自己无意中接受用于具有不同“client_id”的客户端的代码。  

>[en]This protects the client from substitution of the authentication code.  

这保护客户端不必替换认证代码。  




## 3.3. Access Token Scope  
>[en]The authorization and token endpoints allow the client to specify the scope of the access request using the "scope" request parameter.  

授权和令牌端点允许客户端使用“范围”请求参数指定访问请求的范围。  

>[en]In turn, the authorization server uses the "scope" response parameter to inform the client of the scope of the access token issued.  

反过来，授权服务器使用“范围”响应参数向客户端通知发出的访问令牌的范围。  

>[en]The value of the scope parameter is expressed as a list of space- delimited, case-sensitive strings.  

范围参数的值表示为空间分隔的、区分大小写的字符串的列表。  

>[en]The strings are defined by the authorization server.  

字符串由授权服务器定义。  

>[en]If the value contains multiple space-delimited strings, their order does not matter, and each string adds an additional access range to the requested scope.  

如果该值包含多个以空格分隔的字符串，则它们的顺序并不重要，并且每个字符串都向所请求的范围添加了额外的访问范围。  

>[en]scope = scope-token *( SP scope-token ) scope-token = 1*( %x21 / %x23-5B / %x5D-7E ) The authorization server MAY fully or partially ignore the scope requested by the client, based on the authorization server policy or the resource owner's instructions.  

.=.-token*(SP.-token).-token=1*(%x21/%x23-5B/%x5D-7E)授权服务器可以根据授权服务器策略或资源所有者的指令完全或部分地忽略客户端请求的范围。  

>[en]If the issued access token scope is different from the one requested by the client, the authorization server MUST include the "scope" response parameter to inform the client of the actual scope granted.  

如果发布的访问令牌范围与客户端请求的访问令牌范围不同，则授权服务器必须包括“范围”响应参数，以向客户端通知所授予的实际范围。  

>[en]If the client omits the scope parameter when requesting authorization, the authorization server MUST either process the request using a pre-defined default value or fail the request indicating an invalid scope.  

如果客户端在请求授权时省略了范围参数，则授权服务器必须使用预定义的默认值处理请求，或者使指示无效范围的请求失败。  

>[en]The authorization server SHOULD document its scope requirements and default value (if defined).  

授权服务器应记录其范围要求和默认值（如果已定义）。  




# 4. Obtaining Authorization  
>[en]To request an access token, the client obtains authorization from the resource owner.  

为了请求访问令牌，客户端从资源所有者获得授权。  

>[en]The authorization is expressed in the form of an authorization grant, which the client uses to request the access token.  

授权以授权授权的形式来表示，客户端使用它来请求访问令牌。  

>[en]OAuth defines four grant types: authorization code, implicit, resource owner password credentials, and client credentials.  

OAuthe定义了四种授权类型：授权代码、隐式、资源所有者密码凭据和客户端凭据。  

>[en]It also provides an extension mechanism for defining additional grant types.  

它还提供了用于定义附加授予类型的扩展机制。  




## 4.1. Authorization Code Grant  
>[en]The authorization code grant type is used to obtain both access tokens and refresh tokens and is optimized for confidential clients.  

授权代码授予类型用于获得访问令牌和刷新令牌，并为机密客户端进行了优化。  

>[en]Since this is a redirection-based flow, the client must be capable of interacting with the resource owner's user-agent (typically a web browser) and capable of receiving incoming requests (via redirection) from the authorization server.  

因为这是基于重定向的流，所以客户端必须能够与资源所有者的用户代理（通常是web浏览器）交互，并且能够（通过重定向）从授权服务器接收传入的请求。  

>[en]+----------+ | Resource | | Owner | | | +----------+ ^ | (B) +----|-----+ Client Identifier +---------------+ | -+----(A)-- & Redirection URI ---->| | | User- | | Authorization | | Agent -+----(B)-- User authenticates --->| Server | | | | | | -+----(C)-- Authorization Code ---<| | +-|----|---+ +---------------+ | | ^ v (A) (C) | | | | | | ^ v | | +---------+ | | | |>---(D)-- Authorization Code ---------' | | Client | & Redirection URI | | | | | |<---(E)----- Access Token -------------------' +---------+ (w/ Optional Refresh Token) Note: The lines illustrating steps (A), (B), and (C) are broken into two parts as they pass through the user-agent.  

+--------+资源所有者〉-+--+^ ^（b）+----- -+客户端标识符+-------++-+-----（a）和重定向URI ->用户-授权-代理-+-----（b）-用户认证-> Serv*[fys*--+-----（c）-授权码--- <}-+----- -+-++------------+{ ^（a）（c）〉（Ⅴ）→v＋+----e++^＞＞（d）-授权码-------‘客户端→重定向URI＞< ---（E）-Access令牌------------+----+（W/可选刷新令牌）注：说明步骤（a）、（b）和（c）的行是BROK当它们通过用户代理时，分为两部分。  

>[en]Figure 3: Authorization Code Flow Hardt Standards Track [Page 24] RFC 6749 OAuth 2.0 October 2012 The flow illustrated in Figure 3 includes the following steps: (A) The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint.  

图3：授权代码流硬标准跟踪[第24页]RFC 6749 OAuth 2.0 2012年10月2日图3所示的流程包括以下步骤：(A)客户端通过将资源所有者的用户代理引导到授权端点来启动流。  

>[en]The client includes its client identifier, requested scope, local state, and a redirection URI to which the authorization server will send the user-agent back once access is granted (or denied).  

客户端包括其客户端标识符、请求的范围、本地状态和一个重定向URI，授权服务器在授予（或拒绝）访问权限后将向URI发送用户代理。  

>[en](B) The authorization server authenticates the resource owner (via the user-agent) and establishes whether the resource owner grants or denies the client's access request.  

(B)授权服务器验证资源所有者(经由用户代理)并确定资源所有者是否准许或拒绝客户端的访问请求。  

>[en](C) Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the redirection URI provided earlier (in the request or during client registration).  

（c）假设资源所有者允许访问，授权服务器使用先前提供的重定向URI（在请求中或在客户端注册期间）将用户代理重定向到客户端。  

>[en]The redirection URI includes an authorization code and any local state provided by the client earlier.  

重定向URI包括授权码和客户端先前提供的任何本地状态。  

>[en](D) The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step.  

(D)客户端通过包括在前一步骤中接收的授权代码从授权服务器的令牌端点请求访问令牌。  

>[en]When making the request, the client authenticates with the authorization server.  

在进行请求时，客户端与授权服务器进行身份验证。  

>[en]The client includes the redirection URI used to obtain the authorization code for verification.  

客户端包括用于获取验证代码的重定向URI。  

>[en](E) The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C).  

(E)授权服务器验证客户端，验证授权代码，并确保在步骤(C)中接收的重定向URI与用于重定向客户端的URI匹配。  

>[en]If valid, the authorization server responds back with an access token and, optionally, a refresh token.  

如果有效，授权服务器响应访问令牌和可选的刷新令牌。  




### 4.1.1. Authorization Request  
>[en]The client constructs the request URI by adding the following parameters to the query component of the authorization endpoint URI using the "application/x-www-form-urlencoded" format, per Appendix B: response_type REQUIRED.  

客户端通过按照附录B“application/x-www-form-urlencoded”格式向授权端点URI的查询组件添加以下参数来构造请求URI：._type REQUIRED。  

>[en]Value MUST be set to "code".  

值必须设置为“代码”。  

>[en]client_id REQUIRED.  

客户需要。  

>[en]The client identifier as described in Section 2.2.  

客户端标识符，如第2.2节所述。  

>[en]redirect_uri OPTIONAL.  

可选的重定向。  

>[en]As described in Section 3.1.2.  

如第3.1.2节所述。  

>[en]Hardt Standards Track [Page 25] RFC 6749 OAuth 2.0 October 2012 scope OPTIONAL.  

哈尔特标准轨道[第25页] RFC 6749 OAUTH 2 2012年10月范围可选。  

>[en]The scope of the access request as described by Section 3.3.  

如第3.3节所述的访问请求的范围。  

>[en]state RECOMMENDED.  

国家推荐。  

>[en]An opaque value used by the client to maintain state between the request and callback.  

客户机用来在请求和回调之间保持状态的不透明值。  

>[en]The authorization server includes this value when redirecting the user-agent back to the client.  

当将用户代理重定向到客户端时，授权服务器包含此值。  

>[en]The parameter SHOULD be used for preventing cross-site request forgery as described in Section 10.12.  

如第10.12节所述，该参数应用于防止跨站点请求伪造。  

>[en]The client directs the resource owner to the constructed URI using an HTTP redirection response, or by other means available to it via the user-agent.  

客户端使用HTTP重定向响应或者通过用户代理可用的其他方式将资源所有者定向到构造的URI。  

>[en]For example, the client directs the user-agent to make the following HTTP request using TLS (with extra line breaks for display purposes only): GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1 Host: server.example.com The authorization server validates the request to ensure that all required parameters are present and valid.  

例如，客户端指示用户代理使用TLS（仅用于显示目的的额外换行）发出以下HTTP请求：GET/授权？._type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2FcbHTTP/1.1Host:server.example.com授权服务器验证请求以确保所有需要的参数都存在和有效。  

>[en]If the request is valid, the authorization server authenticates the resource owner and obtains an authorization decision (by asking the resource owner or by establishing approval via other means).  

如果请求有效，则授权服务器对资源所有者进行身份验证，并获得授权决策（通过询问资源所有者或通过其他方式建立批准）。  

>[en]When a decision is established, the authorization server directs the user-agent to the provided client redirection URI using an HTTP redirection response, or by other means available to it via the user-agent.  

当建立决策时，授权服务器使用HTTP重定向响应或通过用户代理可用的其他方式将用户代理定向到所提供的客户端重定向URI。  




### 4.1.2. Authorization Response  
>[en]If the resource owner grants the access request, the authorization server issues an authorization code and delivers it to the client by adding the following parameters to the query component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B: code REQUIRED.  

如果资源所有者批准了访问请求，授权服务器根据附录B：代码REQUIRED，发出授权代码并通过使用application/x-www-form-urlencoded（应用程序/x-www-form-urlencoded）格式向重定向URI的查询组件添加以下参数将其传递给客户端。  

>[en]The authorization code generated by the authorization server.  

授权服务器生成的授权代码。  

>[en]The authorization code MUST expire shortly after it is issued to mitigate the risk of leaks.  

授权代码在发布后不久必须过期，以降低泄露风险。  

>[en]A maximum authorization code lifetime of 10 minutes is RECOMMENDED.  

建议最大授权码寿命为10分钟。  

>[en]The client MUST NOT use the authorization code Hardt Standards Track [Page 26] RFC 6749 OAuth 2.0 October 2012 more than once.  

客户端不得使用授权代码HART标准轨道（第26页）RFC 6749 OAuth2 2012年10月不止一次。  

>[en]If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.  

如果授权代码被多次使用，则授权服务器必须拒绝该请求，并且应该（如果可能的话）撤销以前基于该授权代码发布的所有令牌。  

>[en]The authorization code is bound to the client identifier and redirection URI.  

授权代码绑定到客户端标识符和重定向URI。  

>[en]state REQUIRED if the "state" parameter was present in the client authorization request.  

如果在客户端授权请求中存在“状态”参数，则需要状态。  

>[en]The exact value received from the client.  

从客户端接收的确切值。  

>[en]For example, the authorization server redirects the user-agent by sending the following HTTP response: HTTP/1.1 302 Found Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA &state=xyz The client MUST ignore unrecognized response parameters.  

例如，授权服务器通过发送以下HTTP响应重定向用户代理：HTTP/1.1 302找到的位置：http://clit.ExpPul.COM/CB？代码= SPLXROBEZQQYBYS6WXSBIAS和状态= XYZ客户端必须忽略未被识别的响应参数。  

>[en]The authorization code string size is left undefined by this specification.  

授权代码字符串大小未被此规范定义。  

>[en]The client should avoid making assumptions about code value sizes.  

客户端应该避免对代码值大小进行假设。  

>[en]The authorization server SHOULD document the size of any value it issues.  

授权服务器应该记录它所发出的任何值的大小。  




#### 4.1.2.1. Error Response  
>[en]If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.  

如果请求由于丢失、无效或不匹配的重定向URI而失败，或者如果客户端标识符丢失或无效，则授权服务器应将错误通知资源所有者，并且必须不自动将用户代理重定向到无效重定向URI。  

>[en]If the resource owner denies the access request or if the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs the client by adding the following parameters to the query component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B: error REQUIRED.  

如果资源所有者拒绝访问请求，或者如果请求由于丢失或无效重定向URI以外的原因失败，则授权服务器使用“application/x-www-form-urlenco”将下列参数添加到重定向URI的查询组件，从而通知客户端D格式，附录B：需要的错误。  

>[en]A single ASCII [USASCII] error code from the following: invalid_request The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.  

下面的一个ASCII（UASCII）错误代码：SimuldIdRebug：请求缺少所需的参数，包括无效的参数值，包括不止一次的参数，或者是其他格式错误。  

>[en]Hardt Standards Track [Page 27] RFC 6749 OAuth 2.0 October 2012 unauthorized_client The client is not authorized to request an authorization code using this method.  

硬标准跟踪[第27页]RFC 6749 OAuth 2.0 2012年10月2.0 unauthor._client客户端未被授权使用此方法请求授权代码。  

>[en]access_denied The resource owner or authorization server denied the request.  

Access拒绝资源所有者或授权服务器拒绝请求。  

>[en]unsupported_response_type The authorization server does not support obtaining an authorization code using this method.  

授权服务器不支持使用该方法获得授权代码。  

>[en]invalid_scope The requested scope is invalid, unknown, or malformed.  

无效的范围：请求的范围无效、未知或畸形。  

>[en]server_error The authorization server encountered an unexpected condition that prevented it from fulfilling the request.  

授权服务器遇到一个意外的情况，阻止它完成请求。  

>[en](This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.) temporarily_unavailable The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  

（由于无法通过HTTP重定向将500Internal Server Error HTTP状态代码返回给客户端，因此需要此错误代码。）临时_不可用。授权服务器当前由于服务器的临时过载或维护而无法处理请求。  

>[en](This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.) Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.  

（需要此错误代码，因为无法通过HTTP重定向将503服务不可用HTTP状态代码返回给客户端。）错误参数的值必须不包括集合%x20-21/%x23-5B/%x5D-7E之外的字符。  

>[en]error_description OPTIONAL.  

Error描述可选。  

>[en]Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.  

人类可读ASCII[USASCII]文本提供附加信息，用于帮助客户端开发人员理解发生的错误。  

>[en]Values for the "error_description" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.  

“Error描述”参数的值必须不包括集合%X20-21/%X23-5B/%X5D-7E之外的字符。  

>[en]error_uri OPTIONAL.  

Error Suri可选。  

>[en]A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error.  

一个URI，用于标识具有错误信息的人类可读网页，用于向客户端开发人员提供关于错误的附加信息。  

>[en]Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E.  

“error_uri”参数的值必须符合URI引用语法，因此必须不包括集合%x21/%x23-5B/%x5D-7E之外的字符。  

>[en]Hardt Standards Track [Page 28] RFC 6749 OAuth 2.0 October 2012 state REQUIRED if a "state" parameter was present in the client authorization request.  

如果客户端授权请求中存在“state”参数，则硬标准跟踪[第28页]RFC 6749 OAuth 2.0 2012年10月2.0状态REQUIRED。  

>[en]The exact value received from the client.  

从客户端接收的确切值。  




### 4.1.3. Access Token Request  
>[en]The client makes a request to the token endpoint by sending the following parameters using the "application/x-www-form-urlencoded" format per Appendix B with a character encoding of UTF-8 in the HTTP request entity-body: grant_type REQUIRED.  

客户端使用每个附录B“application/x-www-form-urlencoded”格式，在HTTP请求实体-body中使用UTF-8的字符编码向令牌端点发出请求：grant_type REQUIRED。  

>[en]Value MUST be set to "authorization_code".  

值必须设置为“AuthigalIX代码”。  

>[en]code REQUIRED.  

需要代码。  

>[en]The authorization code received from the authorization server.  

从授权服务器接收的授权代码。  

>[en]redirect_uri REQUIRED, if the "redirect_uri" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical.  

如果“redirect_uri”参数包含在授权请求中，如4.1.1节所述，并且它们的值必须相同，则重定向_uri REQUIRED。  

>[en]client_id REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.  

如果客户机不在授权服务器上进行认证，如3.2.1节所述，则需要客户机ID。  

>[en]If the client type is confidential or the client was issued client credentials (or assigned other authentication requirements), the client MUST authenticate with the authorization server as described in Section 3.2.1.  

如果客户机类型是保密的，或者客户机被颁发了客户机凭证（或者被指派了其他身份验证要求），则客户机必须如3.2.1节所述，使用授权服务器进行身份验证。  

>[en]Hardt Standards Track [Page 29] RFC 6749 OAuth 2.0 October 2012 For example, the client makes the following HTTP request using TLS (with extra line breaks for display purposes only): POST /token HTTP/1.1 Host: server.example.com Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW Content-Type: application/x-www-form-urlencoded grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb The authorization server MUST: o require client authentication for confidential clients or for any client that was issued client credentials (or with other authentication requirements), o authenticate the client if client authentication is included, o ensure that the authorization code was issued to the authenticated confidential client, or if the client is public, ensure that the code was issued to "client_id" in the request, o verify that the authorization code is valid, and o ensure that the "redirect_uri" parameter is present if the "redirect_uri" parameter was included in the initial authorization request as described in Section 4.1.1, and if included ensure that their values are identical.  

硬标准跟踪[第29页]RFC 6749 OAuth 2.02012年10月2日，例如，客户端使用TLS（仅用于显示目的的额外换行）发出以下HTTP请求：POST/令牌HTTP/1.1主机：server.example.com授权：BasicczZCaGRSa3F0MzpnWDFmF0M2JW内容类型：application/x-www-form-urlencoded grant_type=authorization_code&code=SplxlOBeZQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb授权服务器必须：o要求对机密客户端或对颁发客户端凭证的任何客户端（或其他客户端）进行客户端身份验证身份验证要求）o如果包括客户端身份验证，则对客户端进行身份验证，o确保授权代码被发布到经过身份验证的机密客户端，或者如果客户端是公共的，则确保在请求中将代码发布到“client_id”，o验证授权如果“redirect_uri”参数包含在4.1.1节描述的初始授权请求中，并且如果包含，则确保“redirect_uri”参数存在，并且如果包含，则确保它们的值相同。  




### 4.1.4. Access Token Response  
>[en]If the access token request is valid and authorized, the authorization server issues an access token and optional refresh token as described in Section 5.1.  

如果访问令牌请求是有效的并被授权的，授权服务器将发布访问令牌和可选的刷新令牌，如5.1节所述。  

>[en]If the request client authentication failed or is invalid, the authorization server returns an error response as described in Section 5.2.  

如果请求客户端身份验证失败或无效，则授权服务器返回如第5.2节中所描述的错误响应。  




## 4.2. Implicit Grant  
>[en]The implicit grant type is used to obtain access tokens (it does not support the issuance of refresh tokens) and is optimized for public clients known to operate a particular redirection URI.  

隐式授权类型用于获取访问令牌（它不支持发布刷新令牌），并为已知操作特定重定向URI的公共客户端进行了优化。  

>[en]These clients are typically implemented in a browser using a scripting language such as JavaScript.  

这些客户端通常使用脚本语言（如JavaScript）在浏览器中实现。  

>[en]Since this is a redirection-based flow, the client must be capable of interacting with the resource owner's user-agent (typically a web browser) and capable of receiving incoming requests (via redirection) from the authorization server.  

因为这是基于重定向的流，所以客户端必须能够与资源所有者的用户代理（通常是web浏览器）交互，并且能够（通过重定向）从授权服务器接收传入的请求。  

>[en]Unlike the authorization code grant type, in which the client makes separate requests for authorization and for an access token, the client receives the access token as the result of the authorization request.  

与授权代码授予类型不同，在授权代码授予类型中，客户端对授权和访问令牌分别进行请求，客户端接收作为授权请求结果的访问令牌。  

>[en]The implicit grant type does not include client authentication, and relies on the presence of the resource owner and the registration of the redirection URI.  

隐式授权类型不包括客户端身份验证，并且依赖于资源所有者的存在和重定向URI的注册。  

>[en]Because the access token is encoded into the redirection URI, it may be exposed to the resource owner and other applications residing on the same device.  

因为访问令牌被编码到重定向URI中，所以它可能被暴露给资源所有者和驻留在同一设备上的其他应用程序。  

>[en]Hardt Standards Track [Page 31] RFC 6749 OAuth 2.0 October 2012 +----------+ | Resource | | Owner | | | +----------+ ^ | (B) +----|-----+ Client Identifier +---------------+ | -+----(A)-- & Redirection URI --->| | | User- | | Authorization | | Agent -|----(B)-- User authenticates -->| Server | | | | | | |<---(C)--- Redirection URI ----<| | | | with Access Token +---------------+ | | in Fragment | | +---------------+ | |----(D)--- Redirection URI ---->| Web-Hosted | | | without Fragment | Client | | | | Resource | | (F) |<---(E)------- Script ---------<| | | | +---------------+ +-|--------+ | | (A) (G) Access Token | | ^ v +---------+ | | | Client | | | +---------+ Note: The lines illustrating steps (A) and (B) are broken into two parts as they pass through the user-agent.  

硬标准跟踪[第31页]RFC6749OAuth2649OAuth2649OAuth2649OAuth2649OAuth2649OAuth2.2012年10月2.02012年10月2.0号+--------------------------------------+|资源||所有者|资源|所有者.||所有者.||所有者..||所有者..|||所有者...|||所有者.----------..|||.||||..||所有者.----------------------.........||||.|||||..|.|..|.|.|.|.|.|||||||||||||||重定向URI----------||||||||||||||||||||||||||||||||||||_C-||||||||_C------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++-|------------+||(A)(G)访问令牌|||v+-------+|||Client|||+---+注意：说明步骤(A)和(B)的线路在通过用户代理时被分成两部分。  

>[en]Figure 4: Implicit Grant Flow Hardt Standards Track [Page 32] RFC 6749 OAuth 2.0 October 2012 The flow illustrated in Figure 4 includes the following steps: (A) The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint.  

图4：隐式授予流硬标准跟踪[第32页]RFC 6749 OAuth 2.0 2012年10月4所示的流程包括以下步骤：(A)客户端通过将资源所有者的用户代理引导到授权端点来启动流。  

>[en]The client includes its client identifier, requested scope, local state, and a redirection URI to which the authorization server will send the user-agent back once access is granted (or denied).  

客户端包括其客户端标识符、请求的范围、本地状态和一个重定向URI，授权服务器在授予（或拒绝）访问权限后将向URI发送用户代理。  

>[en](B) The authorization server authenticates the resource owner (via the user-agent) and establishes whether the resource owner grants or denies the client's access request.  

(B)授权服务器验证资源所有者(经由用户代理)并确定资源所有者是否准许或拒绝客户端的访问请求。  

>[en](C) Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the redirection URI provided earlier.  

(C)假设资源所有者准许访问，授权服务器使用前面提供的重定向URI将用户代理重定向回客户端。  

>[en]The redirection URI includes the access token in the URI fragment.  

重定向URI包括URI片段中的访问令牌。  

>[en](D) The user-agent follows the redirection instructions by making a request to the web-hosted client resource (which does not include the fragment per [RFC2616]).  

(D)用户代理通过向网络托管的客户端资源(不包括每个[RFC2616]的片段)发出请求来遵循重定向指令。  

>[en]The user-agent retains the fragment information locally.  

用户代理在本地保留片段信息。  

>[en](E) The web-hosted client resource returns a web page (typically an HTML document with an embedded script) capable of accessing the full redirection URI including the fragment retained by the user-agent, and extracting the access token (and other parameters) contained in the fragment.  

(E)网络托管的客户端资源返回能够访问包括用户代理保留的片段在内的完整重定向URI的网页(通常是具有嵌入脚本的HTML文档)，并且提取片段中包含的访问令牌(和其他参数)。  

>[en](F) The user-agent executes the script provided by the web-hosted client resource locally, which extracts the access token.  

（f）用户代理在本地执行由Web托管客户端资源提供的脚本，该脚本提取访问令牌。  

>[en](G) The user-agent passes the access token to the client.  

（g）用户代理将访问令牌传递给客户端。  

>[en]See Sections 1.3.2 and 9 for background on using the implicit grant.  

有关使用隐式授权的背景，请参阅1.3.2和9节。  

>[en]See Sections 10.3 and 10.16 for important security considerations when using the implicit grant.  

在使用隐式授权时，请参阅第10.3和10.16节的重要安全考虑事项。  




### 4.2.1. Authorization Request  
>[en]The client constructs the request URI by adding the following parameters to the query component of the authorization endpoint URI using the "application/x-www-form-urlencoded" format, per Appendix B: response_type REQUIRED.  

客户端通过按照附录B“application/x-www-form-urlencoded”格式向授权端点URI的查询组件添加以下参数来构造请求URI：._type REQUIRED。  

>[en]Value MUST be set to "token".  

值必须设置为“令牌”。  

>[en]client_id REQUIRED.  

客户需要。  

>[en]The client identifier as described in Section 2.2.  

客户端标识符，如第2.2节所述。  

>[en]Hardt Standards Track [Page 33] RFC 6749 OAuth 2.0 October 2012 redirect_uri OPTIONAL.  

哈尔特标准轨道[第33页] RFC 6749 OAUTH 2 2012年10月重定向TURURI可选。  

>[en]As described in Section 3.1.2.  

如第3.1.2节所述。  

>[en]scope OPTIONAL.  

可选范围。  

>[en]The scope of the access request as described by Section 3.3.  

如第3.3节所述的访问请求的范围。  

>[en]state RECOMMENDED.  

国家推荐。  

>[en]An opaque value used by the client to maintain state between the request and callback.  

客户机用来在请求和回调之间保持状态的不透明值。  

>[en]The authorization server includes this value when redirecting the user-agent back to the client.  

当将用户代理重定向到客户端时，授权服务器包含此值。  

>[en]The parameter SHOULD be used for preventing cross-site request forgery as described in Section 10.12.  

如第10.12节所述，该参数应用于防止跨站点请求伪造。  

>[en]The client directs the resource owner to the constructed URI using an HTTP redirection response, or by other means available to it via the user-agent.  

客户端使用HTTP重定向响应或者通过用户代理可用的其他方式将资源所有者定向到构造的URI。  

>[en]For example, the client directs the user-agent to make the following HTTP request using TLS (with extra line breaks for display purposes only): GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1 Host: server.example.com The authorization server validates the request to ensure that all required parameters are present and valid.  

例如，客户端指示用户代理使用TLS（仅用于显示目的的额外换行）发出以下HTTP请求：GET/授权？._type=token&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2FcbHTTP/1.1Host:server.example.com授权服务器验证请求以确保所有需要的参数都存在和有效。  

>[en]The authorization server MUST verify that the redirection URI to which it will redirect the access token matches a redirection URI registered by the client as described in Section 3.1.2.  

授权服务器必须验证它将重定向访问令牌的重定向URI是否与客户机注册的重定向URI匹配，如3.1.2节所述。  

>[en]If the request is valid, the authorization server authenticates the resource owner and obtains an authorization decision (by asking the resource owner or by establishing approval via other means).  

如果请求有效，则授权服务器对资源所有者进行身份验证，并获得授权决策（通过询问资源所有者或通过其他方式建立批准）。  

>[en]When a decision is established, the authorization server directs the user-agent to the provided client redirection URI using an HTTP redirection response, or by other means available to it via the user-agent.  

当建立决策时，授权服务器使用HTTP重定向响应或通过用户代理可用的其他方式将用户代理定向到所提供的客户端重定向URI。  




### 4.2.2. Access Token Response  
>[en]If the resource owner grants the access request, the authorization server issues an access token and delivers it to the client by adding the following parameters to the fragment component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B: access_token REQUIRED.  

如果资源所有者批准了访问请求，授权服务器根据附录B，发出访问令牌，并通过使用“application/x-www-form-urlencoded”格式向重定向URI的片段组件添加以下参数将其传递给客户端：access_token REQUI红色。  

>[en]The access token issued by the authorization server.  

授权服务器发出的访问令牌。  

>[en]token_type REQUIRED.  

需要托卡式。  

>[en]The type of the token issued as described in Section 7.1.  

如第7.1节所述发出的令牌类型。  

>[en]Value is case insensitive.  

值是大小写不敏感的。  

>[en]expires_in RECOMMENDED.  

推荐使用ExpRESIL。  

>[en]The lifetime in seconds of the access token.  

访问令牌以秒为单位的生命周期。  

>[en]For example, the value "3600" denotes that the access token will expire in one hour from the time the response was generated.  

例如，值“3600”表示访问令牌将在响应生成后一小时内过期。  

>[en]If omitted, the authorization server SHOULD provide the expiration time via other means or document the default value.  

如果省略，授权服务器应通过其他方式提供到期时间或记录默认值。  

>[en]scope OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.  

范围可选，如果与客户端请求的范围相同，则需要。  

>[en]The scope of the access token as described by Section 3.3.  

访问令牌的范围，如第3.3节所述。  

>[en]state REQUIRED if the "state" parameter was present in the client authorization request.  

如果在客户端授权请求中存在“状态”参数，则需要状态。  

>[en]The exact value received from the client.  

从客户端接收的确切值。  

>[en]The authorization server MUST NOT issue a refresh token.  

授权服务器必须不发出刷新令牌。  

>[en]For example, the authorization server redirects the user-agent by sending the following HTTP response (with extra line breaks for display purposes only): HTTP/1.1 302 Found Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA &state=xyz&token_type=example&expires_in=3600 Developers should note that some user-agents do not support the inclusion of a fragment component in the HTTP "Location" response header field.  

例如，授权服务器通过发送以下HTTP响应来重定向用户代理（仅为了显示目的使用额外的换行）：HTTP/1.1302Found Location：http://example.com/cb\access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&.es_in=3600开发人员应该注意，一些用户代理不支持在HTTP“Location”响应头字段中包含片段组件。  

>[en]Such clients will require using other methods for redirecting the client than a 3xx redirection response -- for example, returning an HTML page that includes a 'continue' button with an action linked to the redirection URI.  

这样的客户端将需要使用除了3xx重定向响应之外的其他方法来重定向客户端——例如，返回一个HTML页面，该页面包含一个带有链接到重定向URI的动作的“继续”按钮。  

>[en]Hardt Standards Track [Page 35] RFC 6749 OAuth 2.0 October 2012 The client MUST ignore unrecognized response parameters.  

哈尔特标准轨道[第35页] RFC 6749 OAuth2 2012年10月客户端必须忽略未被识别的响应参数。  

>[en]The access token string size is left undefined by this specification.  

访问令牌字符串大小未被此规范定义。  

>[en]The client should avoid making assumptions about value sizes.  

客户应避免对价值大小做出假设。  

>[en]The authorization server SHOULD document the size of any value it issues.  

授权服务器应该记录它所发出的任何值的大小。  




#### 4.2.2.1. Error Response  
>[en]If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.  

如果请求由于丢失、无效或不匹配的重定向URI而失败，或者如果客户端标识符丢失或无效，则授权服务器应将错误通知资源所有者，并且必须不自动将用户代理重定向到无效重定向URI。  

>[en]If the resource owner denies the access request or if the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs the client by adding the following parameters to the fragment component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B: error REQUIRED.  

如果资源所有者拒绝访问请求，或者如果请求由于丢失或无效重定向URI以外的原因失败，授权服务器将使用“application/x-www-form-urle”将下列参数添加到重定向URI的片段组件，从而通知客户端N编码“格式，附录B：需要的错误。  

>[en]A single ASCII [USASCII] error code from the following: invalid_request The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.  

下面的一个ASCII（UASCII）错误代码：SimuldIdRebug：请求缺少所需的参数，包括无效的参数值，包括不止一次的参数，或者是其他格式错误。  

>[en]unauthorized_client The client is not authorized to request an access token using this method.  

未授权客户端使用此方法未授权请求访问令牌。  

>[en]access_denied The resource owner or authorization server denied the request.  

Access拒绝资源所有者或授权服务器拒绝请求。  

>[en]unsupported_response_type The authorization server does not support obtaining an access token using this method.  

授权服务器不支持使用此方法获得访问令牌。  

>[en]invalid_scope The requested scope is invalid, unknown, or malformed.  

无效的范围：请求的范围无效、未知或畸形。  

>[en]Hardt Standards Track [Page 36] RFC 6749 OAuth 2.0 October 2012 server_error The authorization server encountered an unexpected condition that prevented it from fulfilling the request.  

硬标准跟踪[第36页]RFC 6749 OAuth 2.0 2012年10月2.0 server_error授权服务器遇到意外情况，阻止它完成请求。  

>[en](This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.) temporarily_unavailable The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  

（由于无法通过HTTP重定向将500Internal Server Error HTTP状态代码返回给客户端，因此需要此错误代码。）临时_不可用。授权服务器当前由于服务器的临时过载或维护而无法处理请求。  

>[en](This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.) Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.  

（需要此错误代码，因为无法通过HTTP重定向将503服务不可用HTTP状态代码返回给客户端。）错误参数的值必须不包括集合%x20-21/%x23-5B/%x5D-7E之外的字符。  

>[en]error_description OPTIONAL.  

Error描述可选。  

>[en]Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.  

人类可读ASCII[USASCII]文本提供附加信息，用于帮助客户端开发人员理解发生的错误。  

>[en]Values for the "error_description" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.  

“Error描述”参数的值必须不包括集合%X20-21/%X23-5B/%X5D-7E之外的字符。  

>[en]error_uri OPTIONAL.  

Error Suri可选。  

>[en]A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error.  

一个URI，用于标识具有错误信息的人类可读网页，用于向客户端开发人员提供关于错误的附加信息。  

>[en]Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E.  

“error_uri”参数的值必须符合URI引用语法，因此必须不包括集合%x21/%x23-5B/%x5D-7E之外的字符。  

>[en]state REQUIRED if a "state" parameter was present in the client authorization request.  

如果在客户端授权请求中存在“状态”参数，则需要状态。  

>[en]The exact value received from the client.  

从客户端接收的确切值。  




## 4.3. Resource Owner Password Credentials Grant  
>[en]The resource owner password credentials grant type is suitable in cases where the resource owner has a trust relationship with the client, such as the device operating system or a highly privileged Hardt Standards Track [Page 37] RFC 6749 OAuth 2.0 October 2012 application.  

资源所有者密码凭证授予类型适用于资源所有者与客户端具有信任关系的情况，例如设备操作系统或高度特权的硬标准轨道[第37页]RFC 6749 OAuth 2012年10月2.0应用程序。  

>[en]The authorization server should take special care when enabling this grant type and only allow it when other flows are not viable.  

授权服务器在启用此授权类型时应特别小心，并且仅当其他流不可行时才允许。  

>[en]This grant type is suitable for clients capable of obtaining the resource owner's credentials (username and password, typically using an interactive form).  

这种授权类型适合于能够获取资源所有者凭据（用户名和密码，通常使用交互式表单）的客户机。  

>[en]It is also used to migrate existing clients using direct authentication schemes such as HTTP Basic or Digest authentication to OAuth by converting the stored credentials to an access token.  

它还用于通过使用直接身份验证方案（如HTTP Basic或Digest身份验证）将存储的凭证转换为访问令牌，将现有客户端迁移到OAuth。  

>[en]+----------+ | Resource | | Owner | | | +----------+ v | Resource Owner (A) Password Credentials | v +---------+ +---------------+ | |>--(B)---- Resource Owner ------->| | | | Password Credentials | Authorization | | Client | | Server | | |<--(C)---- Access Token ---------<| | | | (w/ Optional Refresh Token) | | +---------+ +---------------+ Figure 5: Resource Owner Password Credentials Flow The flow illustrated in Figure 5 includes the following steps: (A) The resource owner provides the client with its username and password.  

+------------------++|资源||所有者|||||||||||----------------------------------+----------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------||(w/可选Refr)esh Token)|||+----------+---------------------------------------------------------------------------------------------------图5所示的流程包括以下步骤：（A）资源所有者向客户机提供其用户名和密码。  

>[en](B) The client requests an access token from the authorization server's token endpoint by including the credentials received from the resource owner.  

(B)客户端通过包括从资源所有者接收的凭证来从授权服务器的令牌端点请求访问令牌。  

>[en]When making the request, the client authenticates with the authorization server.  

在进行请求时，客户端与授权服务器进行身份验证。  

>[en](C) The authorization server authenticates the client and validates the resource owner credentials, and if valid, issues an access token.  

(C)授权服务器对客户端进行身份验证并验证资源所有者凭证，如果有效，则发出访问令牌。  




### 4.3.1. Authorization Request and Response  
>[en]The method through which the client obtains the resource owner credentials is beyond the scope of this specification.  

客户端获得资源所有者凭据的方法超出了本规范的范围。  

>[en]The client MUST discard the credentials once an access token has been obtained.  

一旦获得访问令牌，客户端必须丢弃凭据。  




### 4.3.2. Access Token Request  
>[en]The client makes a request to the token endpoint by adding the following parameters using the "application/x-www-form-urlencoded" format per Appendix B with a character encoding of UTF-8 in the HTTP request entity-body: grant_type REQUIRED.  

客户端使用每个附录B“application/x-www-form-urlencoded”格式，在HTTP请求实体-body中以UTF-8的字符编码向令牌端点添加以下参数：grant_type REQUIRED，从而向令牌端点发出请求。  

>[en]Value MUST be set to "password".  

值必须设置为“密码”。  

>[en]username REQUIRED.  

需要用户名。  

>[en]The resource owner username.  

资源所有者用户名。  

>[en]password REQUIRED.  

需要密码。  

>[en]The resource owner password.  

资源所有者密码。  

>[en]scope OPTIONAL.  

可选范围。  

>[en]The scope of the access request as described by Section 3.3.  

如第3.3节所述的访问请求的范围。  

>[en]If the client type is confidential or the client was issued client credentials (or assigned other authentication requirements), the client MUST authenticate with the authorization server as described in Section 3.2.1.  

如果客户机类型是保密的，或者客户机被颁发了客户机凭证（或者被指派了其他身份验证要求），则客户机必须如3.2.1节所述，使用授权服务器进行身份验证。  

>[en]For example, the client makes the following HTTP request using transport-layer security (with extra line breaks for display purposes only): POST /token HTTP/1.1 Host: server.example.com Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW Content-Type: application/x-www-form-urlencoded grant_type=password&username=johndoe&password=A3ddj3w Hardt Standards Track [Page 39] RFC 6749 OAuth 2.0 October 2012 The authorization server MUST: o require client authentication for confidential clients or for any client that was issued client credentials (or with other authentication requirements), o authenticate the client if client authentication is included, and o validate the resource owner password credentials using its existing password validation algorithm.  

例如，客户机使用传输层安全性发出以下HTTP请求（仅用于显示目的的额外换行）：POST/令牌HTTP/1.1Host：server.example.com授权：BasiczZCaGRSa3F0MzpnWDFmF0M2JW内容类型：application/x-www-form-urlencoded grant_type=passWord和UpReNord= Jord-DOE和密码= A3DDJ3W HART标准轨道[第39页] RFC 6749 OAuth2 2012年10月授权服务器必须：O需要客户机身份验证为机密客户或任何客户端发出客户凭据（或与其他认证要求）如果客户端认证被包含在客户端，则使用其现有的密码验证算法验证资源所有者密码凭据。  

>[en]Since this access token request utilizes the resource owner's password, the authorization server MUST protect the endpoint against brute force attacks (e.g., using rate-limitation or generating alerts).  

由于此访问令牌请求利用资源所有者的密码，授权服务器必须保护端点免受暴力攻击（例如，使用速率限制或生成警报）。  




### 4.3.3. Access Token Response  
>[en]If the access token request is valid and authorized, the authorization server issues an access token and optional refresh token as described in Section 5.1.  

如果访问令牌请求是有效的并被授权的，授权服务器将发布访问令牌和可选的刷新令牌，如5.1节所述。  

>[en]If the request failed client authentication or is invalid, the authorization server returns an error response as described in Section 5.2.  

如果请求客户端身份验证失败或无效，授权服务器将返回第5.2节中描述的错误响应。  




## 4.4. Client Credentials Grant  
>[en]The client can request an access token using only its client credentials (or other supported means of authentication) when the client is requesting access to the protected resources under its control, or those of another resource owner that have been previously arranged with the authorization server (the method of which is beyond the scope of this specification).  

当客户端请求访问其控制下的受保护资源或先前与授权服务一起安排的其他资源所有者的资源时，客户端可以仅使用其客户端凭证（或其他支持的身份验证手段）请求访问令牌。R（其方法超出了本说明书的范围）。  

>[en]Hardt Standards Track [Page 40] RFC 6749 OAuth 2.0 October 2012 The client credentials grant type MUST only be used by confidential clients.  

硬标准轨道[第40页]RFC 6749 OAuth 2.0 2012年10月2.0客户端凭证授予类型必须仅由机密客户端使用。  

>[en]+---------+ +---------------+ | | | | | |>--(A)- Client Authentication --->| Authorization | | Client | | Server | | |<--(B)---- Access Token ---------<| | | | | | +---------+ +---------------+ Figure 6: Client Credentials Flow The flow illustrated in Figure 6 includes the following steps: (A) The client authenticates with the authorization server and requests an access token from the token endpoint.  

+-----------++-------------+|||||||||>-(A)-客户端身份验证-->|授权||客户端|服务器|||||B)-访问令牌-------------------------<|||||--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------->||||||||||||客户端与授权服务器进行身份验证，并从令牌端点请求访问令牌。  

>[en](B) The authorization server authenticates the client, and if valid, issues an access token.  

（b）授权服务器对客户端进行认证，如果有效，则发出访问令牌。  




### 4.4.1. Authorization Request and Response  
>[en]Since the client authentication is used as the authorization grant, no additional authorization request is needed.  

由于客户端认证被用作授权授权，所以不需要额外的授权请求。  




### 4.4.2. Access Token Request  
>[en]The client makes a request to the token endpoint by adding the following parameters using the "application/x-www-form-urlencoded" format per Appendix B with a character encoding of UTF-8 in the HTTP request entity-body: grant_type REQUIRED.  

客户端使用每个附录B“application/x-www-form-urlencoded”格式，在HTTP请求实体-body中以UTF-8的字符编码向令牌端点添加以下参数：grant_type REQUIRED，从而向令牌端点发出请求。  

>[en]Value MUST be set to "client_credentials".  

值必须设置为“clitl凭据”。  

>[en]scope OPTIONAL.  

可选范围。  

>[en]The scope of the access request as described by Section 3.3.  

如第3.3节所述的访问请求的范围。  

>[en]The client MUST authenticate with the authorization server as described in Section 3.2.1.  

客户端必须与授权服务器进行认证，如第3.2.1节所述。  

>[en]Hardt Standards Track [Page 41] RFC 6749 OAuth 2.0 October 2012 For example, the client makes the following HTTP request using transport-layer security (with extra line breaks for display purposes only): POST /token HTTP/1.1 Host: server.example.com Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW Content-Type: application/x-www-form-urlencoded grant_type=client_credentials The authorization server MUST authenticate the client.  

硬标准跟踪[第41页]RFC 6749 OAuth 2.0 2012年10月2.0例如，客户端使用传输层安全性（仅用于显示目的而具有额外的换行符）发出以下HTTP请求：POST/令牌HTTP/1.1主机：server.example.com授权：BasiczZCaGRSa3F0MzpnWDFmQmF0M2JWContent-Type：application/x-www-form-urlencoded grant_type=client_credentials授权服务器必须对客户端进行身份验证。  




### 4.4.3. Access Token Response  
>[en]If the access token request is valid and authorized, the authorization server issues an access token as described in Section 5.1.  

如果访问令牌请求是有效的和授权的，则授权服务器发出一个访问令牌，如第5.1节所述。  

>[en]A refresh token SHOULD NOT be included.  

不应包括刷新令牌。  

>[en]If the request failed client authentication or is invalid, the authorization server returns an error response as described in Section 5.2.  

如果请求客户端身份验证失败或无效，授权服务器将返回第5.2节中描述的错误响应。  




## 4.5. Extension Grants  
>[en]The client uses an extension grant type by specifying the grant type using an absolute URI (defined by the authorization server) as the value of the "grant_type" parameter of the token endpoint, and by adding any additional parameters necessary.  

客户端通过使用绝对URI（由授权服务器定义）指定授权类型作为令牌端点的“grant_type”参数的值，并通过添加任何必要的附加参数，来使用扩展授权类型。  

>[en]Hardt Standards Track [Page 42] RFC 6749 OAuth 2.0 October 2012 For example, to request an access token using a Security Assertion Markup Language (SAML) 2.0 assertion grant type as defined by [OAuth-SAML2], the client could make the following HTTP request using TLS (with extra line breaks for display purposes only): POST /token HTTP/1.1 Host: server.example.com Content-Type: application/x-www-form-urlencoded grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2- bearer&assertion=PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU [...omitted for brevity...]aG5TdGF0ZW1lbnQ-PC9Bc3NlcnRpb24- If the access token request is valid and authorized, the authorization server issues an access token and optional refresh token as described in Section 5.1.  

哈尔特标准轨道[第42页] RFC 6749 OAuth2 2012年10月，例如，使用一个安全断言标记语言（SAML）2断言授权类型，如[OAuth-SAML2]定义的访问令牌，客户端可以使用TLS来执行以下HTTP请求（具有额外的DISP断线）仅供参考：POST/令牌HTTP/1.1主机：服务器.示例.com Content-类型：应用/x-www-表格-ur编码gran-内容-类型：应用/x-www-形式-ur编码gran-内容类型：应用/www-www-www-形式-urlen编码grant_类型：应用/x-www-www-www-www-形式-ur编码grant_类型=urn%3Aietf%3阿阿阿3阿阿阿阿阿阿3阿阿阿阿阿3阿萨ml2承载类型%3承载%3阿萨ml2轴承-承载&断言=PEFzc2Vyc2Vy2Vy2VyBBBJJc3Vy2VyBBBBJCCCCCC3BJJJ3NlcnRpb24-如果访问令牌请求是有效和授权的，授权服务器发布访问令牌和可选刷新令牌，如5.1节所述。  

>[en]If the request failed client authentication or is invalid, the authorization server returns an error response as described in Section 5.2.  

如果请求客户端身份验证失败或无效，授权服务器将返回第5.2节中描述的错误响应。  




# 5. Issuing an Access Token  
>[en]If the access token request is valid and authorized, the authorization server issues an access token and optional refresh token as described in Section 5.1.  

如果访问令牌请求是有效的并被授权的，授权服务器将发布访问令牌和可选的刷新令牌，如5.1节所述。  

>[en]If the request failed client authentication or is invalid, the authorization server returns an error response as described in Section 5.2.  

如果请求客户端身份验证失败或无效，授权服务器将返回第5.2节中描述的错误响应。  




## 5.1. Successful Response  
>[en]The authorization server issues an access token and optional refresh token, and constructs the response by adding the following parameters to the entity-body of the HTTP response with a 200 (OK) status code: access_token REQUIRED.  

授权服务器发出访问令牌和可选的刷新令牌，并通过向具有200（OK）状态代码的HTTP响应的实体-主体添加以下参数来构造响应：access_token REQUIRED。  

>[en]The access token issued by the authorization server.  

授权服务器发出的访问令牌。  

>[en]token_type REQUIRED.  

需要托卡式。  

>[en]The type of the token issued as described in Section 7.1.  

如第7.1节所述发出的令牌类型。  

>[en]Value is case insensitive.  

值是大小写不敏感的。  

>[en]expires_in RECOMMENDED.  

推荐使用ExpRESIL。  

>[en]The lifetime in seconds of the access token.  

访问令牌以秒为单位的生命周期。  

>[en]For example, the value "3600" denotes that the access token will expire in one hour from the time the response was generated.  

例如，值“3600”表示访问令牌将在响应生成后一小时内过期。  

>[en]If omitted, the authorization server SHOULD provide the expiration time via other means or document the default value.  

如果省略，授权服务器应通过其他方式提供到期时间或记录默认值。  

>[en]Hardt Standards Track [Page 43] RFC 6749 OAuth 2.0 October 2012 refresh_token OPTIONAL.  

哈尔特标准轨道[页面43 ] RFC 6749 OAUTH 2 2012年10月刷新令牌可选。  

>[en]The refresh token, which can be used to obtain new access tokens using the same authorization grant as described in Section 6.  

刷新令牌，它可用于使用与第6节中描述的相同授权授予来获得新的访问令牌。  

>[en]scope OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED.  

范围可选，如果与客户端请求的范围相同，则需要。  

>[en]The scope of the access token as described by Section 3.3.  

访问令牌的范围，如第3.3节所述。  

>[en]The parameters are included in the entity-body of the HTTP response using the "application/json" media type as defined by [RFC4627].  

这些参数包括[RFC4627]定义的使用“application/json”媒体类型的HTTP响应的实体-主体中。  

>[en]The parameters are serialized into a JavaScript Object Notation (JSON) structure by adding each parameter at the highest structure level.  

通过在最高结构级别添加每个参数，将参数序列化为JavaScript对象符号（JSON）结构。  

>[en]Parameter names and string values are included as JSON strings.  

参数名称和字符串值被包含为JSON字符串。  

>[en]Numerical values are included as JSON numbers.  

数值包括JSON数。  

>[en]The order of parameters does not matter and can vary.  

参数的顺序并不重要，并且可以变化。  

>[en]The authorization server MUST include the HTTP "Cache-Control" response header field [RFC2616] with a value of "no-store" in any response containing tokens, credentials, or other sensitive information, as well as the "Pragma" response header field [RFC2616] with a value of "no-cache".  

授权服务器必须包括HTTP“Cache-Control”响应报头字段[RFC2616]和值“no-cache”的“Pragma”响应报头字段[RFC2616]，该字段在包含令牌、凭证或其他敏感信息的任何响应中具有“no-store”值。  

>[en]For example: HTTP/1.1 200 OK Content-Type: application/json;charset=UTF-8 Cache-Control: no-store Pragma: no-cache { "access_token":"2YotnFZFEjr1zCsicMWpAA", "token_type":"example", "expires_in":3600, "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA", "example_parameter":"example_value" } The client MUST ignore unrecognized value names in the response.  

例如：HTTP/1.1200OK Content-Type:application/json;charset=UTF-8Cache-Control:no-store Pragma:no-cache{"access_token","2YotnFZFEjr1zCsicMWpAA","token_type","example",".es_in":3600,".esh_token","tGzv3JOkF0XG5Qx2TlKWIA","example_."}客户端MUST ig响应中未识别的值名称。  

>[en]The sizes of tokens and other values received from the authorization server are left undefined.  

从授权服务器接收的令牌和其他值的大小未定义。  

>[en]The client should avoid making assumptions about value sizes.  

客户应避免对价值大小做出假设。  

>[en]The authorization server SHOULD document the size of any value it issues.  

授权服务器应该记录它所发出的任何值的大小。  




## 5.2. Error Response  
>[en]The authorization server responds with an HTTP 400 (Bad Request) status code (unless specified otherwise) and includes the following parameters with the response: error REQUIRED.  

授权服务器使用HTTP 400（Bad Request）状态代码进行响应（除非另有指定），并且包含以下参数作为响应：error REQUIRED。  

>[en]A single ASCII [USASCII] error code from the following: invalid_request The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.  

来自以下内容的单个ASCII[USASCII]错误代码：.._request请求缺少所需的参数，包括不支持的参数值（授权类型除外），重复参数，包括多个凭据，利用多于一个的机制来验证客户端，R是畸形的。  

>[en]invalid_client Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).  

.._client客户端身份验证失败（例如，未知客户端、不包括客户端身份验证或不支持的身份验证方法）。  

>[en]The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported.  

授权服务器可能返回HTTP 401（未授权）状态代码以指示支持哪些HTTP身份验证方案。  

>[en]If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.  

如果客户端试图通过“Authorization”请求报头字段进行身份验证，则授权服务器必须使用HTTP 401(Unauthor.)状态码进行响应，并且包括与客户端使用的身份验证方案匹配的“WWW-Authenticate”响应报头字段。  

>[en]invalid_grant The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.  

所提供的授权授权授权（例如，授权代码、资源所有者凭证）或刷新令牌无效、过期、被撤销、与授权请求中使用的重定向URI不匹配，或者被颁发给另一个客户端。  

>[en]unauthorized_client The authenticated client is not authorized to use this authorization grant type.  

未授权的客户端：未经授权的客户端使用授权授权类型。  

>[en]unsupported_grant_type The authorization grant type is not supported by the authorization server.  

授权服务器不支持授权授予类型。  

>[en]Hardt Standards Track [Page 45] RFC 6749 OAuth 2.0 October 2012 invalid_scope The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.  

硬标准跟踪[第45页]RFC 6749 OAuth 2.0 2012年10月2.0.._.请求的范围无效、未知、格式错误或超过资源所有者授予的范围。  

>[en]Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.  

“错误”参数的值必须不包括集合%X2021/%X23-5B/%X5D-7E之外的字符。  

>[en]error_description OPTIONAL.  

Error描述可选。  

>[en]Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.  

人类可读ASCII[USASCII]文本提供附加信息，用于帮助客户端开发人员理解发生的错误。  

>[en]Values for the "error_description" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.  

“Error描述”参数的值必须不包括集合%X20-21/%X23-5B/%X5D-7E之外的字符。  

>[en]error_uri OPTIONAL.  

Error Suri可选。  

>[en]A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error.  

一个URI，用于标识具有错误信息的人类可读网页，用于向客户端开发人员提供关于错误的附加信息。  

>[en]Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E.  

“error_uri”参数的值必须符合URI引用语法，因此必须不包括集合%x21/%x23-5B/%x5D-7E之外的字符。  

>[en]The parameters are included in the entity-body of the HTTP response using the "application/json" media type as defined by [RFC4627].  

这些参数包括[RFC4627]定义的使用“application/json”媒体类型的HTTP响应的实体-主体中。  

>[en]The parameters are serialized into a JSON structure by adding each parameter at the highest structure level.  

通过在最高结构级别添加每个参数，将参数序列化为JSON结构。  

>[en]Parameter names and string values are included as JSON strings.  

参数名称和字符串值被包含为JSON字符串。  

>[en]Numerical values are included as JSON numbers.  

数值包括JSON数。  

>[en]The order of parameters does not matter and can vary.  

参数的顺序并不重要，并且可以变化。  




# 6. Refreshing an Access Token  
>[en]If the authorization server issued a refresh token to the client, the client makes a refresh request to the token endpoint by adding the following parameters using the "application/x-www-form-urlencoded" format per Appendix B with a character encoding of UTF-8 in the HTTP request entity-body: grant_type REQUIRED.  

如果授权服务器向客户端发出刷新令牌，则客户端通过使用附录B中的“应用程序/XWW-FRAW格式URL编码”格式添加HTTP请求实体正文中的UTF-8字符编码来添加对令牌端点的刷新请求：授予：需要的类型。  

>[en]Value MUST be set to "refresh_token".  

值必须设置为“刷新符号”。  

>[en]refresh_token REQUIRED.  

需要刷新标记。  

>[en]The refresh token issued to the client.  

向客户端发出的刷新令牌。  

>[en]scope OPTIONAL.  

可选范围。  

>[en]The scope of the access request as described by Section 3.3.  

如第3.3节所述的访问请求的范围。  

>[en]The requested scope MUST NOT include any scope not originally granted by the resource owner, and if omitted is treated as equal to the scope originally granted by the resource owner.  

所请求的范围必须不包括最初未由资源所有者授予的任何范围，如果省略，则被视为与资源所有者最初授予的范围相同。  

>[en]Because refresh tokens are typically long-lasting credentials used to request additional access tokens, the refresh token is bound to the client to which it was issued.  

因为刷新令牌通常是用于请求附加访问令牌的持久凭证，所以刷新令牌绑定到向其发布的客户端。  

>[en]If the client type is confidential or the client was issued client credentials (or assigned other authentication requirements), the client MUST authenticate with the authorization server as described in Section 3.2.1.  

如果客户机类型是保密的，或者客户机被颁发了客户机凭证（或者被指派了其他身份验证要求），则客户机必须如3.2.1节所述，使用授权服务器进行身份验证。  

>[en]For example, the client makes the following HTTP request using transport-layer security (with extra line breaks for display purposes only): POST /token HTTP/1.1 Host: server.example.com Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW Content-Type: application/x-www-form-urlencoded grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA Hardt Standards Track [Page 47] RFC 6749 OAuth 2.0 October 2012 The authorization server MUST: o require client authentication for confidential clients or for any client that was issued client credentials (or with other authentication requirements), o authenticate the client if client authentication is included and ensure that the refresh token was issued to the authenticated client, and o validate the refresh token.  

例如，客户机使用传输层安全性发出以下HTTP请求（仅为了显示目的使用额外的换行）：POST/令牌HTTP/1.1Host：server.example.com授权：BasiczZCaGRSa3F0MzpnWDFmF0M2JW内容类型：application/x-www-form-urlencoded grant_type=.esh_token&.esh_token=tGzv3JOkF0XG5Qx2TlKWIA硬标准跟踪[第47页]RFC 6749 OAuth 2.0 2012年10月2日授权服务器必须：o要求对机密客户机或对颁发客户机凭据（或其他身份验证要求）的任何客户机进行客户机身份验证，o如果包括客户端身份验证，则对客户端进行身份验证，并确保将刷新令牌颁发给经过身份验证的客户端，并且验证刷新令牌。  

>[en]If valid and authorized, the authorization server issues an access token as described in Section 5.1.  

如果有效和授权，授权服务器发出访问令牌，如第5.1节所述。  

>[en]If the request failed verification or is invalid, the authorization server returns an error response as described in Section 5.2.  

如果请求失败验证或无效，则授权服务器返回错误响应，如第5.2节所述。  

>[en]The authorization server MAY issue a new refresh token, in which case the client MUST discard the old refresh token and replace it with the new refresh token.  

授权服务器可以发出新的刷新令牌，在这种情况下，客户端必须丢弃旧的刷新令牌并用新的刷新令牌替换它。  

>[en]The authorization server MAY revoke the old refresh token after issuing a new refresh token to the client.  

授权服务器可以在向客户端发布新刷新令牌之后撤销旧刷新令牌。  

>[en]If a new refresh token is issued, the refresh token scope MUST be identical to that of the refresh token included by the client in the request.  

如果发出了新的刷新令牌，则刷新令牌范围必须与请求中包括的客户端刷新令牌的范围相同。  




# 7. Accessing Protected Resources  
>[en]The client accesses protected resources by presenting the access token to the resource server.  

客户端通过将访问令牌呈现给资源服务器来访问受保护资源。  

>[en]The resource server MUST validate the access token and ensure that it has not expired and that its scope covers the requested resource.  

资源服务器必须验证访问令牌，并确保它没有过期，并且其范围覆盖所请求的资源。  

>[en]The methods used by the resource server to validate the access token (as well as any error responses) are beyond the scope of this specification but generally involve an interaction or coordination between the resource server and the authorization server.  

资源服务器用于验证访问令牌（以及任何错误响应）的方法超出了本规范的范围，但通常涉及资源服务器和授权服务器之间的交互或协调。  

>[en]The method in which the client utilizes the access token to authenticate with the resource server depends on the type of access token issued by the authorization server.  

客户端利用访问令牌对资源服务器进行身份验证的方法取决于授权服务器发布的访问令牌的类型。  

>[en]Typically, it involves using the HTTP "Authorization" request header field [RFC2617] with an authentication scheme defined by the specification of the access token type used, such as [RFC6750].  

通常，它涉及使用HTTP“Authorization”请求报头字段[RFC2617]和由所使用的访问令牌类型的规范定义的身份验证方案，例如[RFC6750]。  




## 7.1. Access Token Types  
>[en]The access token type provides the client with the information required to successfully utilize the access token to make a protected resource request (along with type-specific attributes).  

访问令牌类型向客户端提供成功利用访问令牌进行受保护的资源请求（以及特定于类型的属性）所需的信息。  

>[en]The client MUST NOT use an access token if it does not understand the token type.  

如果客户端不理解令牌类型，则不能使用访问令牌。  

>[en]For example, the "bearer" token type defined in [RFC6750] is utilized by simply including the access token string in the request: GET /resource/1 HTTP/1.1 Host: example.com Authorization: Bearer mF_9.B5f-4.1JqM while the "mac" token type defined in [OAuth-HTTP-MAC] is utilized by issuing a Message Authentication Code (MAC) key together with the access token that is used to sign certain components of the HTTP requests: GET /resource/1 HTTP/1.1 Host: example.com Authorization: MAC id="h480djs93hd8", nonce="274312:dj83hs9s", mac="kDZvddkndxvhGRXZhvuDjEWhGeE=" The above examples are provided for illustration purposes only.  

例如，[RFC6750]中定义的“承载”令牌类型通过在请求中包括访问令牌字符串来使用：GET/./1HTTP/1.1Host：example.com Authorization：Bearer mF_9.B5f-4.1JqM，而[OAuth-HTTP-MAC]中定义的“mac”令牌类型通过发出消息来使用。身份验证代码（MAC）密钥和用于对HTTP请求的某些组件进行签名的访问令牌：GET/./1HTTP/1.1Host：example.com授权：MAC id="h480djs93hd8"，nonce="274312:dj83hs9s"，mac="kDZvddkndxvhGRXvGRXZhvDjEWhGeE="以上示例均提供。仅说明插图目的。  

>[en]Developers are advised to consult the [RFC6750] and [OAuth-HTTP-MAC] specifications before use.  

建议开发者在使用之前咨询[RCFC5050]和[OAuthHTTPMAC ]规范。  

>[en]Each access token type definition specifies the additional attributes (if any) sent to the client together with the "access_token" response parameter.  

每个访问令牌类型定义指定发送到客户端的附加属性（如果有的话）以及“access_token”响应参数。  

>[en]It also defines the HTTP authentication method used to include the access token when making a protected resource request.  

它还定义了在保护资源请求时用于包括访问令牌的HTTP身份验证方法。  




## 7.2. Error Response  
>[en]If a resource access request fails, the resource server SHOULD inform the client of the error.  

如果资源访问请求失败，资源服务器应通知客户端错误。  

>[en]While the specifics of such error responses are beyond the scope of this specification, this document establishes a common registry in Section 11.4 for error values to be shared among OAuth token authentication schemes.  

虽然这种错误响应的细节超出了本规范的范围，但是本文档在第11.4节中为要在OAuth令牌认证方案之间共享的错误值建立了一个公共注册中心。  

>[en]New authentication schemes designed primarily for OAuth token authentication SHOULD define a mechanism for providing an error status code to the client, in which the error values allowed are registered in the error registry established by this specification.  

主要为OAuth令牌身份验证设计的新身份验证方案应定义一种机制，用于向客户端提供错误状态代码，其中所允许的错误值被注册在由本规范建立的错误注册表中。  

>[en]Hardt Standards Track [Page 49] RFC 6749 OAuth 2.0 October 2012 Such schemes MAY limit the set of valid error codes to a subset of the registered values.  

硬标准轨道[第49页]RFC 6749OAuth 2012年10月2.0这种方案可以将有效错误代码集限制为注册值的子集。  

>[en]If the error code is returned using a named parameter, the parameter name SHOULD be "error".  

如果使用命名参数返回错误代码，则参数名称应该是“错误”。  

>[en]Other schemes capable of being used for OAuth token authentication, but not primarily designed for that purpose, MAY bind their error values to the registry in the same manner.  

其他能够用于OAuth令牌身份验证的方案（但主要不是为此目的而设计的）可能以相同的方式将它们的错误值绑定到注册中心。  

>[en]New authentication schemes MAY choose to also specify the use of the "error_description" and "error_uri" parameters to return error information in a manner parallel to their usage in this specification.  

新的身份验证方案也可能选择指定使用“error_.”和“error_uri”参数以与它们在本规范中的使用并行的方式返回错误信息。  




# 8. Extensibility  



## 8.1. Defining Access Token Types  
>[en]Access token types can be defined in one of two ways: registered in the Access Token Types registry (following the procedures in Section 11.1), or by using a unique absolute URI as its name.  

访问令牌类型可以通过两种方式之一来定义：在访问令牌类型注册表中注册（遵循第11.1节中的过程），或者使用唯一的绝对URI作为其名称。  

>[en]Types utilizing a URI name SHOULD be limited to vendor-specific implementations that are not commonly applicable, and are specific to the implementation details of the resource server where they are used.  

使用URI名称的类型应限于通常不适用的特定于供应商的实现，并且特定于使用URI名称的资源服务器的实现细节。  

>[en]All other types MUST be registered.  

所有其他类型都必须注册。  

>[en]Type names MUST conform to the type-name ABNF.  

类型名称必须符合类型名称ABNF。  

>[en]If the type definition includes a new HTTP authentication scheme, the type name SHOULD be identical to the HTTP authentication scheme name (as defined by [RFC2617]).  

如果类型定义包括新的HTTP身份验证方案，则类型名称应该与HTTP身份验证方案名称（如[RFC2617]所定义）相同。  

>[en]The token type "example" is reserved for use in examples.  

令牌类型“示例”保留在示例中使用。  




## 8.2. Defining New Endpoint Parameters  
>[en]New request or response parameters for use with the authorization endpoint or the token endpoint are defined and registered in the OAuth Parameters registry following the procedure in Section 11.2.  

用于授权端点或令牌端点的新请求或响应参数按照第11.2节的过程定义并注册在OAuth Parameters注册表中。  

>[en]Parameter names MUST conform to the param-name ABNF, and parameter values syntax MUST be well-defined (e.g., using ABNF, or a reference to the syntax of an existing parameter).  

参数名称必须符合参数名称ABNF，并且参数值语法必须定义得很好（例如，使用ABNF或对现有参数的语法的引用）。  

>[en]param-name = 1*name-char name-char = "-" / "." / "_" / DIGIT / ALPHA Hardt Standards Track [Page 50] RFC 6749 OAuth 2.0 October 2012 Unregistered vendor-specific parameter extensions that are not commonly applicable and that are specific to the implementation details of the authorization server where they are used SHOULD utilize a vendor-specific prefix that is not likely to conflict with other registered values (e.g., begin with 'companyname_').  

param-name=1*name-char name-char="-"/"./""/DIGIT/ALPHA Hardt Standards Track[第50页]RFC 6749 OAuth 2.0 2012年10月2.0日未注册的、通常不适用并且特定于授权服务器的实现细节的参数扩展如果使用它们，应该使用不太可能与其他注册值冲突的特定于供应商的前缀（例如，以“companyname_”开头）。  




## 8.3. Defining New Authorization Grant Types  
>[en]New authorization grant types can be defined by assigning them a unique absolute URI for use with the "grant_type" parameter.  

新的授权授予类型可以通过赋予它们与“GrANTHYTYPE”参数一起使用的唯一绝对URI来定义。  

>[en]If the extension grant type requires additional token endpoint parameters, they MUST be registered in the OAuth Parameters registry as described by Section 11.2.  

如果扩展授权类型需要额外的令牌端点参数，则它们必须按照第11.2节的描述在OAuth Parameters注册表中注册。  




## 8.4. Defining New Authorization Endpoint Response Types  
>[en]New response types for use with the authorization endpoint are defined and registered in the Authorization Endpoint Response Types registry following the procedure in Section 11.3.  

按照第11.3节的过程，在Authorization Endpoint Response Types注册表中定义并注册了用于授权端点的新响应类型。  

>[en]Response type names MUST conform to the response-type ABNF.  

响应类型名称必须符合响应类型ABNF。  

>[en]response-type = response-name *( SP response-name ) response-name = 1*response-char response-char = "_" / DIGIT / ALPHA If a response type contains one or more space characters (%x20), it is compared as a space-delimited list of values in which the order of values does not matter.  

.-type=.-name*(SP.-name).-name=1*.-char.-char=""/DIGIT/ALPHA如果响应类型包含一个或多个空格字符(%x20)，则将其与值顺序无关的空格分隔的值列表进行比较。  

>[en]Only one order of values can be registered, which covers all other arrangements of the same set of values.  

只有一个值的顺序可以注册，它涵盖了所有相同的值集合的其他安排。  

>[en]For example, the response type "token code" is left undefined by this specification.  

例如，响应类型“令牌代码”未被此规范定义。  

>[en]However, an extension can define and register the "token code" response type.  

但是，扩展可以定义和注册“令牌代码”响应类型。  

>[en]Once registered, the same combination cannot be registered as "code token", but both values can be used to denote the same response type.  

一旦注册，相同的组合就不能注册为“代码令牌”，但是两个值都可以用来表示相同的响应类型。  




## 8.5. Defining Additional Error Codes  
>[en]In cases where protocol extensions (i.e., access token types, extension parameters, or extension grant types) require additional error codes to be used with the authorization code grant error response (Section 4.1.2.1), the implicit grant error response (Section 4.2.2.1), the token error response (Section 5.2), or the resource access error response (Section 7.2), such error codes MAY be defined.  

在协议扩展（即，访问令牌类型、扩展参数或扩展授权类型）要求与授权代码授权错误响应（4.1.2.1节）、隐式授权错误响应（4.2.1节）、令牌错误响应（4.2.1节）一起使用的情况下，第5.2节）或资源访问错误响应（第7.2节），可以定义这样的错误代码。  

>[en]Hardt Standards Track [Page 51] RFC 6749 OAuth 2.0 October 2012 Extension error codes MUST be registered (following the procedures in Section 11.4) if the extension they are used in conjunction with is a registered access token type, a registered endpoint parameter, or an extension grant type.  

硬标准跟踪[第51页]RFC 6749 OAuth 2.0 2012年10月2.0扩展错误代码必须被注册（遵循第11.4节中的过程），如果它们一起使用的扩展是注册的访问令牌类型、注册的端点参数或扩展授权类型。  

>[en]Error codes used with unregistered extensions MAY be registered.  

与未注册的扩展一起使用的错误代码可以被注册。  

>[en]Error codes MUST conform to the error ABNF and SHOULD be prefixed by an identifying name when possible.  

错误代码必须符合错误ABNF，并且应在可能的情况下由标识名称前缀。  

>[en]For example, an error identifying an invalid value set to the extension parameter "example" SHOULD be named "example_invalid".  

例如，将一个无效值设置为扩展参数“示例”的错误应该命名为“ExpPultValueID”。  




# 9. Native Applications  
>[en]Native applications are clients installed and executed on the device used by the resource owner (i.e., desktop application, native mobile application).  

本机应用程序是在资源所有者（即，桌面应用程序、本机移动应用程序）使用的设备上安装和执行的客户机。  

>[en]Native applications require special consideration related to security, platform capabilities, and overall end-user experience.  

本地应用需要与安全性、平台能力和整体最终用户体验相关的特殊考虑。  

>[en]The authorization endpoint requires interaction between the client and the resource owner's user-agent.  

授权终结点需要客户端和资源所有者的用户代理之间的交互。  

>[en]Native applications can invoke an external user-agent or embed a user-agent within the application.  

本地应用程序可以调用外部用户代理或在应用程序中嵌入用户代理。  

>[en]For example: o External user-agent - the native application can capture the response from the authorization server using a redirection URI with a scheme registered with the operating system to invoke the client as the handler, manual copy-and-paste of the credentials, running a local web server, installing a user-agent extension, or by providing a redirection URI identifying a server-hosted resource under the client's control, which in turn makes the response available to the native application.  

例如：o外部用户代理——本地应用程序可以使用重定向URI捕获来自授权服务器的响应，该URI具有在操作系统中注册的方案，以调用客户端作为处理程序，手动复制和粘贴凭证，运行本地Web服务器，在停止用户代理扩展，或者通过提供重定向URI来标识客户端控制下的服务器托管资源，这反过来使响应对本地应用程序可用。  

>[en]o Embedded user-agent - the native application obtains the response by directly communicating with the embedded user-agent by monitoring state changes emitted during the resource load, or accessing the user-agent's cookies storage.  

o嵌入式用户代理——本地应用程序通过监视在资源加载期间发出的状态变化或者访问用户代理的cookie存储来与嵌入式用户代理直接通信来获得响应。  

>[en]When choosing between an external or embedded user-agent, developers should consider the following: o An external user-agent may improve completion rate, as the resource owner may already have an active session with the authorization server, removing the need to re-authenticate.  

当在外部用户代理或嵌入式用户代理之间进行选择时，开发人员应该考虑以下几点：o外部用户代理可以提高完成率，因为资源所有者可能已经与授权服务器有一个活动会话，因此不需要重新身份验证。  

>[en]It provides a familiar end-user experience and functionality.  

它提供了一个熟悉的终端用户体验和功能。  

>[en]The Hardt Standards Track [Page 52] RFC 6749 OAuth 2.0 October 2012 resource owner may also rely on user-agent features or extensions to assist with authentication (e.g., password manager, 2-factor device reader).  

硬标准跟踪[第52页]RFC 6749 OAuth 2.0 2012年10月2.0资源所有者还可以依靠用户代理特性或扩展来辅助身份验证（例如，密码管理器、2因素设备读取器）。  

>[en]o An embedded user-agent may offer improved usability, as it removes the need to switch context and open new windows.  

嵌入式用户代理可以提供改进的可用性，因为它消除了切换上下文和打开新窗口的需要。  

>[en]o An embedded user-agent poses a security challenge because resource owners are authenticating in an unidentified window without access to the visual protections found in most external user-agents.  

o嵌入式用户代理提出了一个安全挑战，因为资源所有者在未识别的窗口中进行身份验证，而没有访问大多数外部用户代理中找到的视觉保护。  

>[en]An embedded user-agent educates end-users to trust unidentified requests for authentication (making phishing attacks easier to execute).  

嵌入式用户代理教育终端用户信任身份验证的未标识请求（使得钓鱼攻击更容易执行）。  

>[en]When choosing between the implicit grant type and the authorization code grant type, the following should be considered: o Native applications that use the authorization code grant type SHOULD do so without using client credentials, due to the native application's inability to keep client credentials confidential.  

当在隐式授权类型和授权代码授权类型之间进行选择时，应该考虑以下因素：o使用授权代码授权类型的本地应用程序应该不使用客户端凭证，因为本地应用程序不能保留客户端凭证LS机密。  

>[en]o When using the implicit grant type flow, a refresh token is not returned, which requires repeating the authorization process once the access token expires.  

o当使用隐式授予类型流时，不返回刷新令牌，这需要在访问令牌过期后重复授权过程。  




# 10. Security Considerations  
>[en]As a flexible and extensible framework, OAuth's security considerations depend on many factors.  

作为一个灵活的和可扩展的框架，OAuths的安全考虑取决于许多因素。  

>[en]The following sections provide implementers with security guidelines focused on the three client profiles described in Section 2.1: web application, user-agent-based application, and native application.  

以下各节向实现者提供了安全指南，这些指南集中于第2.1节中描述的三个客户机概要文件：web应用程序、基于用户代理的应用程序和本地应用程序。  

>[en]A comprehensive OAuth security model and analysis, as well as background for the protocol design, is provided by [OAuth-THREATMODEL].  

[OAuth-THREATMODEL]提供了全面的OAuth安全模型和分析，以及协议设计的背景。  




## 10.1. Client Authentication  
>[en]The authorization server establishes client credentials with web application clients for the purpose of client authentication.  

授权服务器与客户端应用程序建立客户端证书以实现客户端认证。  

>[en]The authorization server is encouraged to consider stronger client authentication means than a client password.  

鼓励授权服务器考虑比客户端密码更强的客户端认证方式。  

>[en]Web application clients MUST ensure confidentiality of client passwords and other client credentials.  

Web应用程序客户端必须确保客户端密码和其他客户端凭据的机密性。  

>[en]Hardt Standards Track [Page 53] RFC 6749 OAuth 2.0 October 2012 The authorization server MUST NOT issue client passwords or other client credentials to native application or user-agent-based application clients for the purpose of client authentication.  

硬标准跟踪[第53页]RFC 6749 OAuth 2.0 2012年10月2.0授权服务器必须不向本地应用程序或基于用户代理的应用程序客户端发出客户端密码或其他客户端凭证，以用于客户端身份验证。  

>[en]The authorization server MAY issue a client password or other credentials for a specific installation of a native application client on a specific device.  

授权服务器可以为在特定设备上安装本机应用程序客户端发出客户端密码或其他凭据。  

>[en]When client authentication is not possible, the authorization server SHOULD employ other means to validate the client's identity -- for example, by requiring the registration of the client redirection URI or enlisting the resource owner to confirm identity.  

当无法进行客户端身份验证时，授权服务器应该采用其他方法来验证客户端的身份——例如，通过要求注册客户端重定向URI或征求资源所有者来确认身份。  

>[en]A valid redirection URI is not sufficient to verify the client's identity when asking for resource owner authorization but can be used to prevent delivering credentials to a counterfeit client after obtaining resource owner authorization.  

在请求资源所有者授权时，有效的重定向URI不足以验证客户端的身份，但可以用于防止在获得资源所有者授权之后向凭证客户端传递凭证。  

>[en]The authorization server must consider the security implications of interacting with unauthenticated clients and take measures to limit the potential exposure of other credentials (e.g., refresh tokens) issued to such clients.  

授权服务器必须考虑与未经身份验证的客户端交互的安全影响，并采取措施限制向这些客户机发出的其他凭据（例如，刷新令牌）的潜在暴露。  




## 10.2. Client Impersonation  
>[en]A malicious client can impersonate another client and obtain access to protected resources if the impersonated client fails to, or is unable to, keep its client credentials confidential.  

如果被模拟的客户端未能或无法对其客户机凭证保密，恶意客户机可以模拟另一个客户机并获得对受保护资源的访问。  

>[en]The authorization server MUST authenticate the client whenever possible.  

授权服务器必须在可能的情况下对客户端进行身份验证。  

>[en]If the authorization server cannot authenticate the client due to the client's nature, the authorization server MUST require the registration of any redirection URI used for receiving authorization responses and SHOULD utilize other means to protect resource owners from such potentially malicious clients.  

如果授权服务器由于客户端的性质而不能对客户端进行身份验证，则授权服务器必须要求注册用于接收授权响应的任何重定向URI，并且应当利用其他手段保护资源所有者免受这种潜在的恶意c抵押物。  

>[en]For example, the authorization server can engage the resource owner to assist in identifying the client and its origin.  

例如，授权服务器可以与资源所有者进行合作，以帮助识别客户端及其来源。  

>[en]The authorization server SHOULD enforce explicit resource owner authentication and provide the resource owner with information about the client and the requested authorization scope and lifetime.  

授权服务器应该强制执行显式的资源所有者身份验证，并向资源所有者提供关于客户端以及所请求的授权范围和生存期的信息。  

>[en]It is up to the resource owner to review the information in the context of the current client and to authorize or deny the request.  

由资源所有者在当前客户端的上下文中检查信息并授权或拒绝请求。  

>[en]The authorization server SHOULD NOT process repeated authorization requests automatically (without active resource owner interaction) without authenticating the client or relying on other measures to ensure that the repeated request comes from the original client and not an impersonator.  

授权服务器不应自动（没有活跃的资源所有者交互）处理重复的授权请求，而不对客户端进行身份验证或依赖其他措施以确保重复的请求来自原始客户端而不是模拟器。  




## 10.3. Access Tokens  
>[en]Access token credentials (as well as any confidential access token attributes) MUST be kept confidential in transit and storage, and only shared among the authorization server, the resource servers the access token is valid for, and the client to whom the access token is issued.  

访问令牌凭据（以及任何机密访问令牌属性）必须在传输和存储中保持机密，并且仅在授权服务器、访问令牌有效的资源服务器以及向其颁发访问令牌的客户端之间共享。  

>[en]Access token credentials MUST only be transmitted using TLS as described in Section 1.6 with server authentication as defined by [RFC2818].  

访问令牌凭证必须仅使用第1.6节中描述的TLS，使用[RFC2818]定义的服务器身份验证进行传输。  

>[en]When using the implicit grant type, the access token is transmitted in the URI fragment, which can expose it to unauthorized parties.  

当使用隐式授权类型时，访问令牌在URI片段中传输，URI片段可以将访问令牌暴露给未授权方。  

>[en]The authorization server MUST ensure that access tokens cannot be generated, modified, or guessed to produce valid access tokens by unauthorized parties.  

授权服务器必须确保不能生成、修改或猜测访问令牌，以由未授权方生成有效的访问令牌。  

>[en]The client SHOULD request access tokens with the minimal scope necessary.  

客户端应该以最小的必要范围请求访问令牌。  

>[en]The authorization server SHOULD take the client identity into account when choosing how to honor the requested scope and MAY issue an access token with less rights than requested.  

授权服务器在选择如何遵守所请求的范围时应该考虑客户机标识，并且可以发出比所请求的权限少的访问令牌。  

>[en]This specification does not provide any methods for the resource server to ensure that an access token presented to it by a given client was issued to that client by the authorization server.  

本规范没有为资源服务器提供任何方法，以确保授权服务器向给定客户端颁发了由给定客户端呈现给它的访问令牌。  




## 10.4. Refresh Tokens  
>[en]Authorization servers MAY issue refresh tokens to web application clients and native application clients.  

授权服务器可以向Web应用程序客户端和本地应用程序客户端发布刷新令牌。  

>[en]Refresh tokens MUST be kept confidential in transit and storage, and shared only among the authorization server and the client to whom the refresh tokens were issued.  

刷新令牌必须在传输和存储过程中保持机密，并且仅在授权服务器和发放刷新令牌的客户端之间共享。  

>[en]The authorization server MUST maintain the binding between a refresh token and the client to whom it was issued.  

授权服务器必须维护刷新令牌与它所发出的客户端之间的绑定。  

>[en]Refresh tokens MUST only be transmitted using TLS as described in Section 1.6 with server authentication as defined by [RFC2818].  

刷新令牌必须只使用TLS（如第1.6节所描述的）通过服务器认证（[RCFC1818]）来发送。  

>[en]The authorization server MUST verify the binding between the refresh token and client identity whenever the client identity can be authenticated.  

每当可以验证客户端身份时，授权服务器必须验证刷新令牌和客户端身份之间的绑定。  

>[en]When client authentication is not possible, the authorization server SHOULD deploy other means to detect refresh token abuse.  

当客户端身份验证不可能时，授权服务器应该部署其他方法来检测刷新令牌滥用。  

>[en]For example, the authorization server could employ refresh token rotation in which a new refresh token is issued with every access token refresh response.  

例如，授权服务器可以采用刷新令牌旋转，其中在每个访问令牌刷新响应中发布新的刷新令牌。  

>[en]The previous refresh token is invalidated Hardt Standards Track [Page 55] RFC 6749 OAuth 2.0 October 2012 but retained by the authorization server.  

上一个刷新令牌是失效的硬标准轨道[第55页]RFC 6749 OAuth 2.0 2012年10月2日，但由授权服务器保留。  

>[en]If a refresh token is compromised and subsequently used by both the attacker and the legitimate client, one of them will present an invalidated refresh token, which will inform the authorization server of the breach.  

如果刷新令牌被破坏，并且随后被攻击者和合法客户端都使用，则其中一个将呈现无效的刷新令牌，该令牌将向授权服务器通知违约。  

>[en]The authorization server MUST ensure that refresh tokens cannot be generated, modified, or guessed to produce valid refresh tokens by unauthorized parties.  

授权服务器必须确保刷新令牌不能被生成、修改或猜测为由未授权方生成有效的刷新令牌。  




## 10.5. Authorization Codes  
>[en]The transmission of authorization codes SHOULD be made over a secure channel, and the client SHOULD require the use of TLS with its redirection URI if the URI identifies a network resource.  

授权码的传输应该在安全信道上进行，并且如果URI标识网络资源，则客户端应该要求使用TLS及其重定向URI。  

>[en]Since authorization codes are transmitted via user-agent redirections, they could potentially be disclosed through user-agent history and HTTP referrer headers.  

由于授权代码是通过用户代理重定向传输的，因此它们可能通过用户代理历史和HTTP引用头公开。  

>[en]Authorization codes operate as plaintext bearer credentials, used to verify that the resource owner who granted authorization at the authorization server is the same resource owner returning to the client to complete the process.  

授权代码用作明文承载凭据，用于验证在授权服务器上授予授权的资源所有者是否是返回客户端以完成该过程的同一资源所有者。  

>[en]Therefore, if the client relies on the authorization code for its own resource owner authentication, the client redirection endpoint MUST require the use of TLS.  

因此，如果客户端依赖授权代码进行自己的资源所有者身份验证，则客户端重定向端点必须使用TLS。  

>[en]Authorization codes MUST be short lived and single-use.  

授权代码必须是短命的和一次性使用的。  

>[en]If the authorization server observes multiple attempts to exchange an authorization code for an access token, the authorization server SHOULD attempt to revoke all access tokens already granted based on the compromised authorization code.  

如果授权服务器观察到多次尝试为访问令牌交换授权代码，则授权服务器应尝试撤销基于受损的授权代码已经授予的所有访问令牌。  

>[en]If the client can be authenticated, the authorization servers MUST authenticate the client and ensure that the authorization code was issued to the same client.  

如果可以对客户端进行身份验证，则授权服务器必须对客户端进行身份验证，并确保向同一客户端发出了授权代码。  




## 10.6. Authorization Code Redirection URI Manipulation  
>[en]When requesting authorization using the authorization code grant type, the client can specify a redirection URI via the "redirect_uri" parameter.  

当使用授权代码授予类型请求授权时，客户端可以通过“redirect_uri”参数指定重定向URI。  

>[en]If an attacker can manipulate the value of the redirection URI, it can cause the authorization server to redirect the resource owner user-agent to a URI under the control of the attacker with the authorization code.  

如果攻击者可以操纵重定向URI的值，则可以使授权服务器在攻击者使用授权代码的控制下将资源所有者用户代理重定向到URI。  

>[en]An attacker can create an account at a legitimate client and initiate the authorization flow.  

攻击者可以在合法客户端创建帐户并启动授权流。  

>[en]When the attacker's user-agent is sent to the authorization server to grant access, the attacker grabs the authorization URI provided by the legitimate client and replaces the Hardt Standards Track [Page 56] RFC 6749 OAuth 2.0 October 2012 client's redirection URI with a URI under the control of the attacker.  

当攻击者的用户代理被发送到授权服务器以授予访问权限时，攻击者获取合法客户端提供的授权URI，并将硬标准轨道[第56页]RFC 6749 OAuth 2.0 2012年10月2日客户端的重定向URI替换为受攻击者。  

>[en]The attacker then tricks the victim into following the manipulated link to authorize access to the legitimate client.  

攻击者然后欺骗受害者进入操纵的链接，授权访问合法客户端。  

>[en]Once at the authorization server, the victim is prompted with a normal, valid request on behalf of a legitimate and trusted client, and authorizes the request.  

一旦到达授权服务器，代表合法和可信的客户机向受害者提示一个正常、有效的请求，并对请求进行授权。  

>[en]The victim is then redirected to an endpoint under the control of the attacker with the authorization code.  

然后，在攻击者的控制下，用授权码将受害者重定向到端点。  

>[en]The attacker completes the authorization flow by sending the authorization code to the client using the original redirection URI provided by the client.  

攻击者通过使用客户端提供的原始重定向URI向客户端发送授权代码来完成授权流。  

>[en]The client exchanges the authorization code with an access token and links it to the attacker's client account, which can now gain access to the protected resources authorized by the victim (via the client).  

客户端使用访问令牌交换授权代码，并将其链接到攻击者的客户端帐户，该客户端帐户现在可以（通过客户端）访问受害者授权的受保护资源。  

>[en]In order to prevent such an attack, the authorization server MUST ensure that the redirection URI used to obtain the authorization code is identical to the redirection URI provided when exchanging the authorization code for an access token.  

为了防止这种攻击，授权服务器必须确保用于获得授权代码的重定向URI与在交换访问令牌的授权代码时提供的重定向URI相同。  

>[en]The authorization server MUST require public clients and SHOULD require confidential clients to register their redirection URIs.  

授权服务器必须要求公共客户端，并且应该要求机密客户端注册其重定向URI。  

>[en]If a redirection URI is provided in the request, the authorization server MUST validate it against the registered value.  

如果在请求中提供了重定向URI，则授权服务器必须根据注册值验证该URI。  




## 10.7. Resource Owner Password Credentials  
>[en]The resource owner password credentials grant type is often used for legacy or migration reasons.  

资源所有者密码凭据授予类型通常用于遗留或迁移原因。  

>[en]It reduces the overall risk of storing usernames and passwords by the client but does not eliminate the need to expose highly privileged credentials to the client.  

它降低了客户端存储用户名和密码的总体风险，但不消除向客户端公开高特权凭证的需要。  

>[en]This grant type carries a higher risk than other grant types because it maintains the password anti-pattern this protocol seeks to avoid.  

这种授权类型比其他授权类型具有更高的风险，因为它维护了该协议试图避免的密码反模式。  

>[en]The client could abuse the password, or the password could unintentionally be disclosed to an attacker (e.g., via log files or other records kept by the client).  

客户端可能滥用密码，或者密码可能无意中泄露给攻击者（例如，通过客户端保存的日志文件或其他记录）。  

>[en]Additionally, because the resource owner does not have control over the authorization process (the resource owner's involvement ends when it hands over its credentials to the client), the client can obtain access tokens with a broader scope than desired by the resource owner.  

此外，由于资源所有者对授权过程没有控制权（资源所有者的参与在将其凭证交给客户端时结束），因此客户端可以获得比资源所有者期望的范围更广的访问令牌。  

>[en]The authorization server should consider the scope and lifetime of access tokens issued via this grant type.  

授权服务器应该考虑通过这种授予类型发布的访问令牌的范围和生存期。  

>[en]The authorization server and client SHOULD minimize use of this grant type and utilize other grant types whenever possible.  

授权服务器和客户端应尽量减少使用此授予类型，并尽可能使用其他授予类型。  




## 10.8. Request Confidentiality  
>[en]Access tokens, refresh tokens, resource owner passwords, and client credentials MUST NOT be transmitted in the clear.  

访问标记、刷新令牌、资源所有者密码和客户端凭据不能在清除中传输。  

>[en]Authorization codes SHOULD NOT be transmitted in the clear.  

授权代码不应在清除中传输。  

>[en]The "state" and "scope" parameters SHOULD NOT include sensitive client or resource owner information in plain text, as they can be transmitted over insecure channels or stored insecurely.  

“状态”和“范围”参数不应包括明文形式的敏感客户端或资源所有者信息，因为它们可以通过不安全的通道传输或不安全地存储。  




## 10.9. Ensuring Endpoint Authenticity  
>[en]In order to prevent man-in-the-middle attacks, the authorization server MUST require the use of TLS with server authentication as defined by [RFC2818] for any request sent to the authorization and token endpoints.  

为了防止中间人攻击，授权服务器必须要求对发送到授权和令牌端点的任何请求使用具有[RFC2818]定义的服务器认证的TLS。  

>[en]The client MUST validate the authorization server's TLS certificate as defined by [RFC6125] and in accordance with its requirements for server identity authentication.  

客户端必须根据[RFC6125]定义的授权服务器的TLS证书并根据其对服务器身份验证的要求，对其进行验证。  




## 10.10. Credentials-Guessing Attacks  
>[en]The authorization server MUST prevent attackers from guessing access tokens, authorization codes, refresh tokens, resource owner passwords, and client credentials.  

授权服务器必须防止攻击者猜测访问令牌、授权代码、刷新令牌、资源所有者密码和客户端凭据。  

>[en]The probability of an attacker guessing generated tokens (and other credentials not intended for handling by end-users) MUST be less than or equal to 2^(-128) and SHOULD be less than or equal to 2^(-160).  

攻击者猜测生成的令牌（以及不打算由最终用户处理的其他凭据）的概率必须小于或等于2^（-128），并且应该小于或等于2^（-160）。  

>[en]The authorization server MUST utilize other means to protect credentials intended for end-user usage.  

授权服务器必须利用其他手段来保护最终用户使用的证书。  




## 10.11. Phishing Attacks  
>[en]Wide deployment of this and similar protocols may cause end-users to become inured to the practice of being redirected to websites where they are asked to enter their passwords.  

这种和类似协议的广泛部署可能导致最终用户习惯于被重定向到要求他们输入密码的网站。  

>[en]If end-users are not careful to verify the authenticity of these websites before entering their credentials, it will be possible for attackers to exploit this practice to steal resource owners' passwords.  

如果最终用户在输入其凭证之前不仔细地验证这些网站的真实性，那么攻击者可能会利用这种做法来窃取资源所有者的密码。  

>[en]Service providers should attempt to educate end-users about the risks phishing attacks pose and should provide mechanisms that make it easy for end-users to confirm the authenticity of their sites.  

服务提供商应试图教育终端用户钓鱼攻击带来的风险，并应提供使终端用户易于确认其站点的真实性的机制。  

>[en]Client developers should consider the security implications of how they interact with the user-agent (e.g., external, embedded), and the ability of the end-user to verify the authenticity of the authorization server.  

客户端开发人员应该考虑它们如何与用户代理（例如，外部的、嵌入的）交互的安全隐含性，以及最终用户验证授权服务器的真实性的能力。  

>[en]Hardt Standards Track [Page 58] RFC 6749 OAuth 2.0 October 2012 To reduce the risk of phishing attacks, the authorization servers MUST require the use of TLS on every endpoint used for end-user interaction.  

哈尔特标准轨道[第58页] RFC 6749 OAuth2 2012年10月以减少网络钓鱼攻击的风险，授权服务器必须要求在最终用户交互使用的每个端点上使用TLS。  




## 10.12. Cross-Site Request Forgery  
>[en]Cross-site request forgery (CSRF) is an exploit in which an attacker causes the user-agent of a victim end-user to follow a malicious URI (e.g., provided to the user-agent as a misleading link, image, or redirection) to a trusting server (usually established via the presence of a valid session cookie).  

跨站点请求伪造(CSRF)是攻击者使受害者最终用户的用户代理跟随恶意URI(例如，作为误导性链接、图像或重定向提供给用户代理)到信任服务器(通常通过有效会话烹饪器的存在而建立)的漏洞。IE）。  

>[en]A CSRF attack against the client's redirection URI allows an attacker to inject its own authorization code or access token, which can result in the client using an access token associated with the attacker's protected resources rather than the victim's (e.g., save the victim's bank account information to a protected resource controlled by the attacker).  

针对客户端重定向URI的CSRF攻击允许攻击者注入其自身的授权代码或访问令牌，这可能导致客户端使用与攻击者的受保护资源相关联的访问令牌而不是受害者的资源（例如，保存受害者的银行账户信息）。离子被攻击者控制的受保护资源。  

>[en]The client MUST implement CSRF protection for its redirection URI.  

客户端必须为其重定向URI实现CSRF保护。  

>[en]This is typically accomplished by requiring any request sent to the redirection URI endpoint to include a value that binds the request to the user-agent's authenticated state (e.g., a hash of the session cookie used to authenticate the user-agent).  

这通常通过要求发送到重定向URI端点的任何请求包括将请求绑定到用户代理的认证状态的值（例如，用于认证用户代理的会话cookie的散列）来实现。  

>[en]The client SHOULD utilize the "state" request parameter to deliver this value to the authorization server when making an authorization request.  

当发出授权请求时，客户端应该利用“state”请求参数向授权服务器传递此值。  

>[en]Once authorization has been obtained from the end-user, the authorization server redirects the end-user's user-agent back to the client with the required binding value contained in the "state" parameter.  

一旦从最终用户获得了授权，授权服务器就用包含在“state”参数中的所需绑定值将最终用户的用户代理重定向回客户端。  

>[en]The binding value enables the client to verify the validity of the request by matching the binding value to the user-agent's authenticated state.  

绑定值使客户端能够通过将绑定值与用户代理的认证状态匹配来验证请求的有效性。  

>[en]The binding value used for CSRF protection MUST contain a non-guessable value (as described in Section 10.10), and the user-agent's authenticated state (e.g., session cookie, HTML5 local storage) MUST be kept in a location accessible only to the client and the user-agent (i.e., protected by same-origin policy).  

用于CSRF保护的绑定值必须包含不可猜测的值（如第10.10节所述），并且用户代理的认证状态（例如，会话cookie、HTML5本地存储）必须保持在仅对客户端和用户代理可访问的位置（即，受到相同或相同的保护）。IGIN政策。  

>[en]A CSRF attack against the authorization server's authorization endpoint can result in an attacker obtaining end-user authorization for a malicious client without involving or alerting the end-user.  

针对授权服务器的授权端点的CSRF攻击可导致攻击者获得针对恶意客户端的最终用户授权，而不涉及或警告最终用户。  

>[en]The authorization server MUST implement CSRF protection for its authorization endpoint and ensure that a malicious client cannot obtain authorization without the awareness and explicit consent of the resource owner.  

授权服务器必须为其授权端点实现CSRF保护，并确保恶意客户端在没有资源所有者的意识和明确同意的情况下不能获得授权。  




## 10.13. Clickjacking  
>[en]In a clickjacking attack, an attacker registers a legitimate client and then constructs a malicious site in which it loads the authorization server's authorization endpoint web page in a transparent iframe overlaid on top of a set of dummy buttons, which are carefully constructed to be placed directly under important buttons on the authorization page.  

在单击劫持攻击中，攻击者注册一个合法的客户端，然后构建一个恶意站点，在该站点中，它以一个透明的iframe加载授权服务器的授权端点网页，该iframe覆盖在一组虚拟按钮之上，这些虚拟按钮被仔细构造为被置于direc。在授权页面上的重要按钮下。  

>[en]When an end-user clicks a misleading visible button, the end-user is actually clicking an invisible button on the authorization page (such as an "Authorize" button).  

当最终用户单击误导的可见按钮时，最终用户实际上是在单击授权页面上的不可见按钮（例如“Author.”按钮）。  

>[en]This allows an attacker to trick a resource owner into granting its client access without the end-user's knowledge.  

这允许攻击者欺骗资源所有者在没有最终用户的知识的情况下授予其客户端访问权。  

>[en]To prevent this form of attack, native applications SHOULD use external browsers instead of embedding browsers within the application when requesting end-user authorization.  

为了防止这种形式的攻击，当请求最终用户授权时，本机应用程序应该使用外部浏览器而不是将浏览器嵌入到应用程序中。  

>[en]For most newer browsers, avoidance of iframes can be enforced by the authorization server using the (non-standard) "x-frame-options" header.  

对于大多数较新的浏览器，授权服务器可以使用（非标准）“x-frame-.”头强制避免iframe。  

>[en]This header can have two values, "deny" and "sameorigin", which will block any framing, or framing by sites with a different origin, respectively.  

这个标头可以具有两个值“deny”和“sameorigin”，这两个值将分别阻塞任何框架，或者根据具有不同来源的站点进行框架。  

>[en]For older browsers, JavaScript frame-busting techniques can be used but may not be effective in all browsers.  

对于旧浏览器，可以使用JavaScript框架破译技术，但在所有浏览器中都可能无效。  




## 10.14. Code Injection and Input Validation  
>[en]A code injection attack occurs when an input or otherwise external variable is used by an application unsanitized and causes modification to the application logic.  

当未初始化的应用程序使用输入或其他外部变量并导致对应用程序逻辑的修改时，就会发生代码注入攻击。  

>[en]This may allow an attacker to gain access to the application device or its data, cause denial of service, or introduce a wide range of malicious side-effects.  

这可能允许攻击者访问应用程序设备或其数据、造成拒绝服务或引入广泛的恶意副作用。  

>[en]The authorization server and client MUST sanitize (and validate when possible) any value received -- in particular, the value of the "state" and "redirect_uri" parameters.  

授权服务器和客户端必须清除（并在可能时验证）接收到的任何值——尤其是“state”和“redirect_uri”参数的值。  




## 10.15. Open Redirectors  
>[en]The authorization server, authorization endpoint, and client redirection endpoint can be improperly configured and operate as open redirectors.  

授权服务器、授权端点和客户端重定向端点可能配置不当，并作为打开重定向器操作。  

>[en]An open redirector is an endpoint using a parameter to automatically redirect a user-agent to the location specified by the parameter value without any validation.  

打开重定向器是使用参数自动将用户代理重定向到由参数值指定的位置而无需任何验证的端点。  

>[en]Open redirectors can be used in phishing attacks, or by an attacker to get end-users to visit malicious sites by using the URI authority component of a familiar and trusted destination.  

开放重定向器可用于钓鱼攻击，或者由攻击者使用熟悉和可信的目的地的URI权限组件来让终端用户访问恶意站点。  

>[en]In addition, if the authorization server allows the client to register only part of the redirection URI, an attacker can use an open redirector operated by Hardt Standards Track [Page 60] RFC 6749 OAuth 2.0 October 2012 the client to construct a redirection URI that will pass the authorization server validation but will send the authorization code or access token to an endpoint under the control of the attacker.  

此外，如果授权服务器允许客户端仅注册部分重定向URI，则攻击者可以使用由Hardt Standards Track[Page 60]RFC 6749 OAuth 2.0 2012年10月2日客户端操作的开放重定向器来构造将通过授权服务的重定向URI。ER验证，但将发送授权代码或访问令牌到攻击者的控制下的端点。  




## 10.16. Misuse of Access Token to Impersonate Resource Owner in Implicit  
>[en]Flow For public clients using implicit flows, this specification does not provide any method for the client to determine what client an access token was issued to.  

对于使用隐式流的公共客户端，此规范不为客户端提供任何方法来确定向哪个客户端发出了访问令牌。  

>[en]A resource owner may willingly delegate access to a resource by granting an access token to an attacker's malicious client.  

资源所有者可以通过向攻击者的恶意客户端授予访问令牌来自愿地访问资源。  

>[en]This may be due to phishing or some other pretext.  

这可能是由于网络钓鱼或其他借口。  

>[en]An attacker may also steal a token via some other mechanism.  

攻击者也可以通过其他机制盗取令牌。  

>[en]An attacker may then attempt to impersonate the resource owner by providing the access token to a legitimate public client.  

攻击者可以尝试通过向合法公共客户端提供访问令牌来模拟资源所有者。  

>[en]In the implicit flow (response_type=token), the attacker can easily switch the token in the response from the authorization server, replacing the real access token with the one previously issued to the attacker.  

在隐式流（._type=token）中，攻击者可以容易地切换来自授权服务器的响应中的令牌，用先前发布给攻击者的令牌替换实际访问令牌。  

>[en]Servers communicating with native applications that rely on being passed an access token in the back channel to identify the user of the client may be similarly compromised by an attacker creating a compromised application that can inject arbitrary stolen access tokens.  

与依赖于在后通道中传递访问令牌来标识客户端用户的本地应用程序进行通信的服务器可能同样受到创建可注入任意被盗访问令牌的受害应用程序的攻击者的破坏。  

>[en]Any public client that makes the assumption that only the resource owner can present it with a valid access token for the resource is vulnerable to this type of attack.  

假设只有资源所有者可以向其提供资源的有效访问令牌的任何公共客户端都易受这种攻击类型的影响。  

>[en]This type of attack may expose information about the resource owner at the legitimate client to the attacker (malicious client).  

这种类型的攻击可以将合法客户端上的资源所有者的信息暴露给攻击者（恶意客户端）。  

>[en]This will also allow the attacker to perform operations at the legitimate client with the same permissions as the resource owner who originally granted the access token or authorization code.  

这也将允许攻击者以与最初授予访问令牌或授权代码的资源所有者相同的权限在合法客户端上执行操作。  

>[en]Authenticating resource owners to clients is out of scope for this specification.  

将资源所有者认证给客户端不在本规范的范围内。  

>[en]Any specification that uses the authorization process as a form of delegated end-user authentication to the client (e.g., third-party sign-in service) MUST NOT use the implicit flow without additional security mechanisms that would enable the client to determine if the access token was issued for its use (e.g., audience- restricting the access token).  

使用授权过程作为委托给客户端的最终用户身份验证形式的任何规范（例如，第三方登录服务）必须不使用隐式流，而不需要额外的安全机制，这些机制将使客户端能够确定是否针对i.TS使用（例如，观众限制访问令牌）。  




# 11. IANA Considerations  



## 11.1. OAuth Access Token Types Registry  
>[en]This specification establishes the OAuth Access Token Types registry.  

此规范建立OAuthAccess令牌类型注册表。  

>[en]Access token types are registered with a Specification Required ([RFC5226]) after a two-week review period on the oauth-ext-review@ietf.org mailing list, on the advice of one or more Designated Experts.  

在一个或多个指定专家的建议下，在oauth-ext-.@ietf.org邮件列表上经过两周的审查之后，访问令牌类型被注册到Specification Required([RFC5226])。  

>[en]However, to allow for the allocation of values prior to publication, the Designated Expert(s) may approve registration once they are satisfied that such a specification will be published.  

然而，为了允许在发布之前分配值，一旦指定专家确信将公布这样的规范，他们就可以批准注册。  

>[en]Registration requests must be sent to the oauth-ext-review@ietf.org mailing list for review and comment, with an appropriate subject (e.g., "Request for access token type: example").  

注册请求必须发送到oauth-ext-.@ietf.org邮寄列表以供审查和评论，并带有适当的主题（例如，“请求访问令牌类型：示例”）。  

>[en]Within the review period, the Designated Expert(s) will either approve or deny the registration request, communicating this decision to the review list and IANA.  

在审查期内，指定专家将批准或拒绝注册请求，将该决定传达给审查清单和IANA。  

>[en]Denials should include an explanation and, if applicable, suggestions as to how to make the request successful.  

拒绝应该包括一个解释，如果适用的话，关于如何使请求成功的建议。  

>[en]IANA must only accept registry updates from the Designated Expert(s) and should direct all requests for registration to the review mailing list.  

IANA必须只接受指定专家的注册表更新，并应将所有注册请求引导到审查邮件列表。  




### 11.1.1. Registration Template  
>[en]Type name: The name requested (e.g., "example").  

类型名称：请求的名称（例如，“示例”）。  

>[en]Additional Token Endpoint Response Parameters: Additional response parameters returned together with the "access_token" parameter.  

附加令牌端点响应参数：与“Access令牌”参数一起返回的附加响应参数。  

>[en]New parameters MUST be separately registered in the OAuth Parameters registry as described by Section 11.2.  

新参数必须在OAUTH参数注册表中单独注册，如第11.2节所述。  

>[en]HTTP Authentication Scheme(s): The HTTP authentication scheme name(s), if any, used to authenticate protected resource requests using access tokens of this type.  

HTTP认证方案（S）：HTTP认证方案名称（s），如果有的话，用于使用这种类型的访问令牌来验证受保护的资源请求。  

>[en]Change controller: For Standards Track RFCs, state "IETF".  

更改控制器：对于标准轨道RFCS，状态“IETF”。  

>[en]For others, give the name of the responsible party.  

对于其他人，给出责任方的名称。  

>[en]Other details (e.g., postal address, email address, home page URI) may also be included.  

还可以包括其他细节（例如，邮政地址、电子邮件地址、主页URI）。  

>[en]Hardt Standards Track [Page 62] RFC 6749 OAuth 2.0 October 2012 Specification document(s): Reference to the document(s) that specify the parameter, preferably including a URI that can be used to retrieve a copy of the document(s).  

硬标准轨道[第62页]RFC 6749 OAuth 2.0 2012年10月2.0规范文档：参考指定参数的文档，优选地包括可用于检索文档副本的URI。  

>[en]An indication of the relevant sections may also be included but is not required.  

也可以包括相关部分的指示，但不需要。  




## 11.2. OAuth Parameters Registry  
>[en]This specification establishes the OAuth Parameters registry.  

本规范建立了OAuth参数注册表。  

>[en]Additional parameters for inclusion in the authorization endpoint request, the authorization endpoint response, the token endpoint request, or the token endpoint response are registered with a Specification Required ([RFC5226]) after a two-week review period on the oauth-ext-review@ietf.org mailing list, on the advice of one or more Designated Experts.  

在oauth-ext-.@ietf.org邮寄的两周审查期之后，将用于包括在授权端点请求、授权端点响应、令牌端点请求或令牌端点响应中的其他参数注册到Specification Required([RFC5226])。名单上，一个或多个指定专家的意见。  

>[en]However, to allow for the allocation of values prior to publication, the Designated Expert(s) may approve registration once they are satisfied that such a specification will be published.  

然而，为了允许在发布之前分配值，一旦指定专家确信将公布这样的规范，他们就可以批准注册。  

>[en]Registration requests must be sent to the oauth-ext-review@ietf.org mailing list for review and comment, with an appropriate subject (e.g., "Request for parameter: example").  

注册请求必须发送到oauth-ext-.@ietf.org邮寄列表以供审查和评论，并带有适当的主题（例如，“Request for.：example”）。  

>[en]Within the review period, the Designated Expert(s) will either approve or deny the registration request, communicating this decision to the review list and IANA.  

在审查期内，指定专家将批准或拒绝注册请求，将该决定传达给审查清单和IANA。  

>[en]Denials should include an explanation and, if applicable, suggestions as to how to make the request successful.  

拒绝应该包括一个解释，如果适用的话，关于如何使请求成功的建议。  

>[en]IANA must only accept registry updates from the Designated Expert(s) and should direct all requests for registration to the review mailing list.  

IANA必须只接受指定专家的注册表更新，并应将所有注册请求引导到审查邮件列表。  




### 11.2.1. Registration Template  
>[en]Parameter name: The name requested (e.g., "example").  

参数名：请求的名称（例如，“示例”）。  

>[en]Parameter usage location: The location(s) where parameter can be used.  

参数使用位置：可以使用参数的位置。  

>[en]The possible locations are authorization request, authorization response, token request, or token response.  

可能的位置是授权请求、授权响应、令牌请求或令牌响应。  

>[en]Change controller: For Standards Track RFCs, state "IETF".  

更改控制器：对于标准轨道RFCS，状态“IETF”。  

>[en]For others, give the name of the responsible party.  

对于其他人，给出责任方的名称。  

>[en]Other details (e.g., postal address, email address, home page URI) may also be included.  

还可以包括其他细节（例如，邮政地址、电子邮件地址、主页URI）。  

>[en]Hardt Standards Track [Page 63] RFC 6749 OAuth 2.0 October 2012 Specification document(s): Reference to the document(s) that specify the parameter, preferably including a URI that can be used to retrieve a copy of the document(s).  

哈尔特标准轨道[第63页] RFC 6749 OAuth2 2012年10月规范文档（S）：引用指定参数的文档（S），优选地包括可用于检索文档副本的URI。  

>[en]An indication of the relevant sections may also be included but is not required.  

也可以包括相关部分的指示，但不需要。  




### 11.2.2. Initial Registry Contents  



## 11.3. OAuth Authorization Endpoint Response Types Registry  
>[en]This specification establishes the OAuth Authorization Endpoint Response Types registry.  

本规范建立了OAuthAdvices端点响应类型注册表。  

>[en]Additional response types for use with the authorization endpoint are registered with a Specification Required ([RFC5226]) after a two-week review period on the oauth-ext-review@ietf.org mailing list, on the advice of one or more Designated Experts.  

根据一个或多个指定专家的建议，在oauth-ext-.@ietf.org邮件列表上经过两周的审查之后，在Specification Required([RFC5226])中注册用于授权端点的其他响应类型。  

>[en]However, to allow for the allocation of values prior to publication, the Designated Expert(s) may approve registration once they are satisfied that such a specification will be published.  

然而，为了允许在发布之前分配值，一旦指定专家确信将公布这样的规范，他们就可以批准注册。  

>[en]Registration requests must be sent to the oauth-ext-review@ietf.org mailing list for review and comment, with an appropriate subject (e.g., "Request for response type: example").  

注册请求必须发送到oauth-ext-.@ietf.org邮寄列表以供审查和评论，并带有适当的主题（例如，“请求响应类型：示例”）。  

>[en]Within the review period, the Designated Expert(s) will either approve or deny the registration request, communicating this decision to the review list and IANA.  

在审查期内，指定专家将批准或拒绝注册请求，将该决定传达给审查清单和IANA。  

>[en]Denials should include an explanation and, if applicable, suggestions as to how to make the request successful.  

拒绝应该包括一个解释，如果适用的话，关于如何使请求成功的建议。  

>[en]IANA must only accept registry updates from the Designated Expert(s) and should direct all requests for registration to the review mailing list.  

IANA必须只接受指定专家的注册表更新，并应将所有注册请求引导到审查邮件列表。  




### 11.3.1. Registration Template  
>[en]Response type name: The name requested (e.g., "example").  

响应类型名称：请求的名称（例如，“示例”）。  

>[en]Change controller: For Standards Track RFCs, state "IETF".  

更改控制器：对于标准轨道RFCS，状态“IETF”。  

>[en]For others, give the name of the responsible party.  

对于其他人，给出责任方的名称。  

>[en]Other details (e.g., postal address, email address, home page URI) may also be included.  

还可以包括其他细节（例如，邮政地址、电子邮件地址、主页URI）。  

>[en]Specification document(s): Reference to the document(s) that specify the type, preferably including a URI that can be used to retrieve a copy of the document(s).  

规范文档：指明类型的文档，最好包括可用于检索文档副本的URI。  

>[en]An indication of the relevant sections may also be included but is not required.  

也可以包括相关部分的指示，但不需要。  




### 11.3.2. Initial Registry Contents  



## 11.4. OAuth Extensions Error Registry  
>[en]This specification establishes the OAuth Extensions Error registry.  

本规范建立了OAuthExpple错误注册表。  

>[en]Additional error codes used together with other protocol extensions (i.e., extension grant types, access token types, or extension parameters) are registered with a Specification Required ([RFC5226]) after a two-week review period on the oauth-ext-review@ietf.org mailing list, on the advice of one or more Designated Experts.  

在oauth-ext-.@ietf.org邮件列表上经过两周的审查之后，根据其中一个建议，将连同其他协议扩展（即，扩展授权类型、访问令牌类型或扩展参数）一起使用的其他错误代码注册到规范要求（[RFC5226]）中。或更多指定专家。  

>[en]However, to allow for the allocation of values prior to publication, the Designated Expert(s) may approve registration once they are satisfied that such a specification will be published.  

然而，为了允许在发布之前分配值，一旦指定专家确信将公布这样的规范，他们就可以批准注册。  

>[en]Registration requests must be sent to the oauth-ext-review@ietf.org mailing list for review and comment, with an appropriate subject (e.g., "Request for error code: example").  

注册请求必须发送到oauth-ext-.@ietf.org邮寄列表以供审查和评论，并带有适当的主题（例如，“请求错误代码：示例”）。  

>[en]Within the review period, the Designated Expert(s) will either approve or deny the registration request, communicating this decision to the review list and IANA.  

在审查期内，指定专家将批准或拒绝注册请求，将该决定传达给审查清单和IANA。  

>[en]Denials should include an explanation and, if applicable, suggestions as to how to make the request successful.  

拒绝应该包括一个解释，如果适用的话，关于如何使请求成功的建议。  

>[en]IANA must only accept registry updates from the Designated Expert(s) and should direct all requests for registration to the review mailing list.  

IANA必须只接受指定专家的注册表更新，并应将所有注册请求引导到审查邮件列表。  




### 11.4.1. Registration Template  
>[en]Error name: The name requested (e.g., "example").  

错误名称：请求的名称（例如，“示例”）。  

>[en]Values for the error name MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.  

错误名称的值必须不包括集合%X2021/%X23-5B/%X5D-7E之外的字符。  

>[en]Error usage location: The location(s) where the error can be used.  

错误使用位置：可以使用错误的位置。  

>[en]The possible locations are authorization code grant error response (Section 4.1.2.1), implicit grant error response (Section 4.2.2.1), token error response (Section 5.2), or resource access error response (Section 7.2).  

可能的位置是授权码授予错误响应（第4.1.2.1节）、隐式授权错误响应（第4.2.2.1节）、令牌错误响应（第5.2节）或资源访问错误响应（第7.2节）。  

>[en]Related protocol extension: The name of the extension grant type, access token type, or extension parameter that the error code is used in conjunction with.  

相关协议扩展：与错误代码结合使用的扩展授权类型、访问令牌类型或扩展参数的名称。  

>[en]Change controller: For Standards Track RFCs, state "IETF".  

更改控制器：对于标准轨道RFCS，状态“IETF”。  

>[en]For others, give the name of the responsible party.  

对于其他人，给出责任方的名称。  

>[en]Other details (e.g., postal address, email address, home page URI) may also be included.  

还可以包括其他细节（例如，邮政地址、电子邮件地址、主页URI）。  

>[en]Specification document(s): Reference to the document(s) that specify the error code, preferably including a URI that can be used to retrieve a copy of the document(s).  

规范文档：对指定错误代码的文档的引用，最好包括可用于检索文档副本的URI。  

>[en]An indication of the relevant sections may also be included but is not required.  

也可以包括相关部分的指示，但不需要。  




# 12. References  



## 12.1. Normative References  
>[en][RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.  

[RFC2119] Bradner，S，“在RFC中使用的关键词来指示需求水平”，BCP 14，RFC 2119，1997年3月。  

>[en][RFC2246] Dierks, T.  

[RCF2246]迪尔克斯，T.  

>[en]and C.  

C.  

>[en]Allen, "The TLS Protocol Version 1.0", RFC 2246, January 1999.  

艾伦，“TLS协议版本1”，RFC 2246，1999年1月。  

>[en][RFC2616] Fielding, R., Gettys, J., Mogul, J., Frystyk, H., Masinter, L., Leach, P., and T.  

[RCF2616]菲尔丁，R，Gettys，J.，MuGul，J.，FryStuk，H，MasTeL.L.，LACH，P，T。  

>[en]Berners-Lee, "Hypertext Transfer Protocol -- HTTP/1.1", RFC 2616, June 1999.  

Berners Lee，“超文本传输协议--HTTP／1.1”，RFC 2616，1999年6月。  

>[en][RFC2617] Franks, J., Hallam-Baker, P., Hostetler, J., Lawrence, S., Leach, P., Luotonen, A., and L.  

[RCF2617]弗兰克斯，J.，哈勒姆贝克，P，Hoototter，J，劳伦斯，S，LEACH，P，LooToNon，A.和L。  

>[en]Stewart, "HTTP Authentication: Basic and Digest Access Authentication", RFC 2617, June 1999.  

斯图尔特，“HTTP认证：基本和摘要访问认证”，RFC 2617，1999年6月。  

>[en]Hardt Standards Track [Page 68] RFC 6749 OAuth 2.0 October 2012 [RFC2818] Rescorla, E., "HTTP Over TLS", RFC 2818, May 2000.  

哈尔特标准轨道[第68页] RFC 6749 OAUTH 2 2012年10月[ RFC28 18] RESCOLA，E，“HTTP超过TLS”，RFC 2818，2000年5月。  

>[en][RFC3629] Yergeau, F., "UTF-8, a transformation format of ISO 10646", STD 63, RFC 3629, November 2003.  

[RFC3629 ] Yergeau，F，“UTF-8，ISO 10646的转换格式”，STD 63，RFC 3629，2003年11月。  

>[en][RFC3986] Berners-Lee, T., Fielding, R., and L.  

[RCFC986] Berners Lee，T.，菲尔丁，R，L。  

>[en]Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986, January 2005.  

MasTIN，“统一资源标识符（URI）：通用语法”，STD 66，RFC 3986，2005年1月。  

>[en][RFC4627] Crockford, D., "The application/json Media Type for JavaScript Object Notation (JSON)", RFC 4627, July 2006.  

[RFC4627 ] Crockford，D，“JavaScript对象符号（JSON）的应用程序/JSON媒体类型”，RFC 4627，2006年7月。  

>[en][RFC4949] Shirey, R., "Internet Security Glossary, Version 2", RFC 4949, August 2007.  

[RFC49 49 ] Shirey，R，“互联网安全词汇表，第2版”，RFC 4949，2007年8月。  

>[en][RFC5226] Narten, T.  

[RCF5226] NARTEN，T.  

>[en]and H.  

H.  

>[en]Alvestrand, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 5226, May 2008.  

FounStruts，“在RFC中编写IANA考虑部分的指南”，BCP 26，RFC 5226，2008年5月。  

>[en][RFC5234] Crocker, D.  

[RCF5244] Crocker，D.  

>[en]and P.  

P.  

>[en]Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.  

ObELL，“增强BNF的语法规范：ABNF”，STD 68，RFC 5234，2008年1月。  

>[en][RFC5246] Dierks, T.  

[RCF5246]迪尔克斯，T.  

>[en]and E.  

E.  

>[en]Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.2", RFC 5246, August 2008.  

RESCOLA，“传输层安全（TLS）协议版本1.2”，RFC 5246，2008年8月。  

>[en][RFC6125] Saint-Andre, P.  

[RCF6125] Saint Andre，P.  

>[en]and J.  

J.  

>[en]Hodges, "Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)", RFC 6125, March 2011.  

Hodges，“在传输层安全(TLS)上下文中使用X.509(PKIX)证书在因特网公钥基础设施内表示和验证基于域的应用服务身份”，RFC 6125，2011年3月。  

>[en][USASCII] American National Standards Institute, "Coded Character Set -- 7-bit American Standard Code for Information Interchange", ANSI X3.4, 1986.  

美国国家标准协会，“编码字符集——7位美国信息交换标准代码”，ANSI X3.4，1986。  

>[en][W3C.REC-html401-19991224] Raggett, D., Le Hors, A., and I.  

[W3C.RC-HTML401-1999 91224 ] Raggett，D，Le HORS，A和I。  

>[en]Jacobs, "HTML 4.01 Specification", World Wide Web Consortium Recommendation REC-html401-19991224, December 1999, <http://www.w3.org/TR/1999/REC-html401-19991224>.  

雅各布，“HTML 4.01规范”，万维网联盟建议REC-html401-19991224，1999年12月，<http://www.w3.org/TR/1999/REC-html401-19991224>。  

>[en][W3C.REC-xml-20081126] Bray, T., Paoli, J., Sperberg-McQueen, C., Maler, E., and F.  

[W3C.RC-XML-200 81126]布雷，T，佩奥利，J.，斯皮尔伯格麦奎因，C.，Maler，E和F.  

>[en]Yergeau, "Extensible Markup Language (XML) 1.0 (Fifth Edition)", World Wide Web Consortium Recommendation REC-xml-20081126, November 2008, <http://www.w3.org/TR/2008/REC-xml-20081126>.  

Yergeau，“可扩展标记语言（XML）1.0（第五版）”，万维网联盟推荐REC-xml-20081126，2008年11月，<http://www.w3.org/TR/2008/REC-xml-20081126>。  




## 12.2. Informative References  
