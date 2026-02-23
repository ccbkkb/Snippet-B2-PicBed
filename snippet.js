const DEBUG = false;  // 生产环境改为 false 关闭调试日志和 API

const B2_REGION = "us-west-004"; 
const B2_ENDPOINT = `s3.${B2_REGION}.backblazeb2.com`; 
const B2_BUCKET = "your-private-bucket-name"; // ← 改成你的真实桶名！

const AWS_ACCESS_KEY_ID = "你的_keyID";
const AWS_SECRET_ACCESS_KEY = "你的_applicationKey";

// 签名密钥（必须和生成 sign 的地方完全一致）
const SIGN_SECRET = "your_very_strong_random_secret_key_here_change_this_immediately_2026";

const CACHE_DURATION_SECONDS = 31536000;

export default {
  async fetch(request, env, ctx) {
    try {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
            "Access-Control-Max-Age": "86400",
          }
        });
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      const url = new URL(request.url);

      // ==================== DEBUG SIGN API（仅 DEBUG=true 时可用） ====================
      if (DEBUG && url.pathname === "/__debug/sign") {
        const fileParam = url.searchParams.get("path") || url.searchParams.get("file");
        if (!fileParam) {
          return new Response("Missing parameter: path or file", { status: 400 });
        }
        const expStr = url.searchParams.get("exp");

        let normalizedPath = fileParam.startsWith("/") ? fileParam : "/" + fileParam;

        const sign = await computeSignature(normalizedPath, expStr, SIGN_SECRET);

        return new Response(sign, {
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Access-Control-Allow-Origin": "*"
          }
        });
      }

      const path = url.pathname === "/" ? "/index.html" : url.pathname;

      if (DEBUG) {
        console.log(`[DEBUG] 请求路径: ${path}`);
      }

      // ===== 签名验证 =====
      const sign = url.searchParams.get("sign");
      const expStr = url.searchParams.get("exp");

      if (!sign) {
        if (DEBUG) console.log("[DEBUG] 无 sign 参数 → 直接 404");
        return new Response("Not Found (missing sign)", {
          status: 404,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=7200, s-maxage=7200",
            "CDN-Cache-Control": "max-age=7200",
            "x-debug-reason": "missing-sign",
            "x-snippets-cache": "no-sign"
          }
        });
      }

      const isValid = await validateSignature(path, sign, expStr, SIGN_SECRET);

      if (!isValid) {
        if (DEBUG) {
          console.log("[DEBUG] 签名验证失败");
          console.log(`[DEBUG] 提供的 sign: ${sign}`);
        }
        return new Response("Not Found (invalid sign)", {
          status: 404,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=7200, s-maxage=7200",
            "CDN-Cache-Control": "max-age=7200",
            "x-debug-reason": "invalid-sign",
            "x-snippets-cache": "invalid-sign"
          }
        });
      }

      if (DEBUG) console.log("[DEBUG] 签名通过 → 请求 B2");

      // 忽略查询参数做缓存 key
      const cacheUrl = new URL(url.origin + path);
      cacheUrl.search = '';
      const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
      const cache = caches.default;

      let response = await cache.match(cacheKey);

      if (!response) {
        const b2Url = `https://${B2_BUCKET}.${B2_ENDPOINT}${path}`;
        const signedHeaders = await signV4(b2Url, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, B2_REGION);

        const b2Response = await fetch(b2Url, {
          method: request.method,
          headers: signedHeaders
        });

        if (b2Response.ok || b2Response.status === 304) {
          response = new Response(b2Response.body, b2Response);

          // ──────────────── 自动识别并设置合适的响应头 ────────────────
          const lowerPath = path.toLowerCase();
          const ext = lowerPath.split('.').pop() || '';

          let contentType = b2Response.headers.get("Content-Type") || "application/octet-stream";

          // 如果 B2 返回的 Content-Type 不理想，则根据扩展名覆盖（优先级更高）
          if (contentType === "application/octet-stream" || contentType.startsWith("binary/")) {
            if (["jpg", "jpeg"].includes(ext)) contentType = "image/jpeg";
            else if (ext === "png") contentType = "image/png";
            else if (ext === "gif") contentType = "image/gif";
            else if (ext === "webp") contentType = "image/webp";
            else if (ext === "svg") contentType = "image/svg+xml";
            else if (ext === "bmp") contentType = "image/bmp";
            else if (["tif", "tiff"].includes(ext)) contentType = "image/tiff";
            else if (ext === "pdf") contentType = "application/pdf";
            else if (ext === "txt") contentType = "text/plain; charset=utf-8";
            else if (ext === "html" || ext === "htm") contentType = "text/html; charset=utf-8";
            else if (ext === "json") contentType = "application/json";
            else if (ext === "css") contentType = "text/css";
            else if (ext === "js") contentType = "application/javascript";
            // 其他类型保持 B2 原样或 octet-stream
          }

          response.headers.set("Content-Type", contentType);

          // 只对图片类内容强制 inline，其他文件让浏览器/B2 决定（通常 attachment 或根据类型）
          const imageExts = ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "tif", "tiff"];
          if (imageExts.includes(ext)) {
            response.headers.set("Content-Disposition", "inline");
          }
          // 非图片不设置 Content-Disposition（保持原有行为，避免强制内嵌 pdf 等）

          response.headers.set("Cache-Control", "public, max-age=31536000, s-maxage=31536000, immutable");
          response.headers.set("x-snippets-cache", "stored-success");

          if (DEBUG) {
            console.log(`[DEBUG] Content-Type 设置为: ${contentType}`);
            console.log(`[DEBUG] Content-Disposition: ${imageExts.includes(ext) ? "inline" : "(未设置，保持原有)"}`);
          }
        } 
        else if ([404, 403, 502, 500].includes(b2Response.status)) {
          const errorBody = await b2Response.text();
          response = new Response(errorBody || "Error from B2", {
            status: b2Response.status,
            statusText: b2Response.statusText,
            headers: {
              "Content-Type": "text/plain; charset=utf-8",
              "Cache-Control": "public, max-age=7200, s-maxage=7200",
              "CDN-Cache-Control": "max-age=7200",
              "Access-Control-Allow-Origin": "*",
              "x-snippets-cache": `stored-error-${b2Response.status}`
            }
          });
        } 
        else {
          return b2Response;
        }

        // 存缓存
        try {
          if (request.method === "GET") {
            await cache.put(cacheKey, response.clone());
          }
        } catch (cacheErr) {
          response.headers.set("x-cache-put-error", cacheErr.message.replace(/\n/g, " "));
        }
      } 
      else {
        response = new Response(response.body, response);
        response.headers.set("Access-Control-Allow-Origin", "*");
        response.headers.set("x-snippets-cache", "hit");
      }

      // 调试头
      if (DEBUG) {
        response.headers.set("x-debug-mode", "enabled");
        response.headers.set("x-debug-request-path", path);
        response.headers.set("x-debug-b2-bucket", B2_BUCKET);
        response.headers.set("x-debug-sign-checked", "yes");
      }

      return response;

    } catch (err) {
      if (DEBUG) console.error("[CRITICAL]", err);
      return new Response(
        "CRITICAL ERROR\n" + err.message + "\n" + err.stack,
        { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
      );
    }
  }
};

// ──────────────── 签名相关函数（不变） ────────────────
async function computeSignature(path, expStr, secret) {
  let message = path;
  if (expStr) message = `${path}|${expStr}`;
  try {
    const sigArray = await hmac(secret, message);
    return toHex(sigArray);
  } catch (e) {
    return `ERROR:${e.message}`;
  }
}

async function validateSignature(path, providedSign, expStr, secret) {
  if (typeof providedSign !== "string" || providedSign.length < 8) return false;
  const computed = await computeSignature(path, expStr, secret);
  return computed === providedSign;
}

const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

async function hmac(key, string) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? new TextEncoder().encode(key) : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(string));
  return new Uint8Array(signature);
}

async function hash(string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(string));
  return new Uint8Array(digest);
}

function toHex(buffer) {
  return Array.from(buffer).map(b => b.toString(16).padStart(2, "0")).join("");
}

function awsUriEncode(path) {
  return path.split('/').map(segment => {
    let dec = segment;
    try { dec = decodeURIComponent(segment); } catch(e) {}
    return encodeURIComponent(dec).replace(/[!'()*]/g, function(c) {
      return '%' + c.charCodeAt(0).toString(16).toUpperCase();
    });
  }).join('/');
}

async function signV4(url, accessKeyId, secretAccessKey, region) {
  const urlObj = new URL(url);
  const host = urlObj.host;
  const canonicalUri = awsUriEncode(urlObj.pathname);
  
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStr = amzDate.substring(0, 8);
  const service = "s3";

  const canonicalQueryString = "";
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${EMPTY_HASH}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  
  const canonicalRequest = `GET\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${EMPTY_HASH}`;
  const hashedCanonicalRequest = toHex(await hash(canonicalRequest));

  const credentialScope = `${dateStr}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${hashedCanonicalRequest}`;

  const kDate = await hmac(`AWS4${secretAccessKey}`, dateStr);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, "aws4_request");
  
  const signature = toHex(await hmac(kSigning, stringToSign));
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    "Authorization": authorization,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": EMPTY_HASH
  };
}
