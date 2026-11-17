import type { MetadataRoute } from "next";

// This application is not publicly launched; keep test and account pages out
// of crawler indexes. This is crawler guidance, not an access-control measure.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      disallow: "/",
    },
  };
}
