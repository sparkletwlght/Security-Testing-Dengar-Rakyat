import type { MetadataRoute } from "next";

// No public pages are intended for indexing before the application launches.
export default function sitemap(): MetadataRoute.Sitemap {
  return [];
}
