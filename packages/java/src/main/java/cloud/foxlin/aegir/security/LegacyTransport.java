// Copyright Foxlin Industries.
package cloud.foxlin.aegir.security;
import java.net.*;import java.net.http.*;import java.io.*;import java.nio.*;import java.util.*;import java.util.concurrent.*;import java.time.Duration;import java.security.*;import java.security.cert.*;import javax.net.ssl.*;
final class LegacyTransport{
 static HttpClient create(ExecutorService executor,Duration timeout,String pin)throws Exception{
  HttpClient.Builder b=HttpClient.newBuilder().executor(executor).connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).proxy(new ProxySelector(){public List<Proxy>select(URI u){return Collections.singletonList(Proxy.NO_PROXY);}public void connectFailed(URI u,SocketAddress a,IOException e){}});
  SSLParameters parameters=new SSLParameters();parameters.setProtocols(new String[]{"TLSv1.3","TLSv1.2"});parameters.setEndpointIdentificationAlgorithm("HTTPS");b.sslParameters(parameters);
  if(pin!=null){byte[] expected=AuthorizationIntegration.unhex(pin);SSLContext context=SSLContext.getInstance("TLS");context.init(null,new TrustManager[]{new X509TrustManager(){public X509Certificate[]getAcceptedIssuers(){return new X509Certificate[0];}public void checkClientTrusted(X509Certificate[]c,String a)throws CertificateException{throw new CertificateException("Client certificate unsupported.");}public void checkServerTrusted(X509Certificate[]c,String a)throws CertificateException{try{if(c==null||c.length==0)throw new CertificateException("Certificate missing.");c[0].checkValidity();if(!MessageDigest.isEqual(expected,MessageDigest.getInstance("SHA-256").digest(c[0].getEncoded())))throw new CertificateException("Certificate pin mismatch.");}catch(CertificateException e){throw e;}catch(Exception e){throw new CertificateException("Certificate unavailable.");}}}},null);b.sslContext(context);}
  return b.build();
 }
 static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]>{
  private final CompletableFuture<byte[]> result=new CompletableFuture<>();private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();private Flow.Subscription subscription;
  public CompletionStage<byte[]>getBody(){return result;}
  public void onSubscribe(Flow.Subscription s){subscription=s;s.request(1);}
  public void onNext(List<ByteBuffer>buffers){for(ByteBuffer buffer:buffers){if(bytes.size()+buffer.remaining()>1048576){subscription.cancel();result.completeExceptionally(new IOException("Response limit exceeded."));return;}byte[]part=new byte[buffer.remaining()];buffer.get(part);bytes.write(part,0,part.length);}subscription.request(1);}
  public void onError(Throwable e){result.completeExceptionally(new IOException("Response unavailable."));}public void onComplete(){result.complete(bytes.toByteArray());}
 }
}
