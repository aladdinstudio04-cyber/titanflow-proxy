export default {
  async fetch(request) {
    const url = new URL(request.url);

    // 1. Health check for the root domain
    if (url.pathname === "/" || url.pathname === "") {
      return new Response("TitanFlow TMDB Proxy Active", { status: 200 });
    }

    // 2. Make it a TRUE transparent proxy (Replaces your worker domain with TMDB)
    url.hostname = "api.themoviedb.org";
    
    // 3. Prevent the "/3/3/" crash bug! 
    // If your app already sent /3/, leave it. If not, add it safely.
    if (!url.pathname.startsWith('/3/')) {
        let cleanPath = url.pathname.startsWith('/') ? url.pathname : '/' + url.pathname;
        url.pathname = '/3' + cleanPath;
    }

    // 4. Inject your secret API key safely on the backend
    url.searchParams.set("api_key", "8552258b6703b77b3b3a7d2f58d20e8c");

    try {
      // 5. Fetch exactly what the Android app asked for
      const response = await fetch(url.toString(), request);
      
      const newResponse = new Response(response.body, response);
      newResponse.headers.set("Access-Control-Allow-Origin", "*");
      return newResponse;

    } catch (error) {
      // 6. Failsafe: Return empty JSON so the Android app never crashes on an HTML error page
      return new Response(JSON.stringify({ success: false, results: [] }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
  }
};
