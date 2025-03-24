import { defineStackbitConfig, SiteMapEntry } from "@stackbit/types";

export default defineStackbitConfig({
  stackbitVersion: "~0.6.0",
  ssgName: "custom",
  nodeVersion: "18",
  contentSources: [
    {
      name: "pages",
      sources: [
        {
          name: "pages",
          handler: {
            file: "content/pages.json"
          }
        }
      ]
    }
  ],
  modelExtensions: [
    { 
      name: "Page", 
      type: "page", 
      urlPath: "/{slug}" 
    },
    { 
      name: "Product", 
      type: "page", 
      urlPath: "/product/{slug}" 
    },
    { 
      name: "Category", 
      type: "page", 
      urlPath: "/catalog/{slug}" 
    }
  ],
  siteMap: ({ documents, models }) => {
    const pageModels = models.filter((m) => m.type === "page");

    return documents
      .filter((d) => pageModels.some(m => m.name === d.modelName))
      .map((document) => {
        const urlModel = (() => {
          switch (document.modelName) {
            case 'Page':
              return '';
            case 'Product':
              return 'product';
            case 'Category':
              return 'catalog';
            default:
              return null;
          }
        })();

        return {
          stableId: document.id,
          urlPath: urlModel ? `/${urlModel}/${document.slug}` : `/${document.slug}`,
          document,
          isHomePage: document.slug === 'home'
        };
      })
      .filter(Boolean) as SiteMapEntry[];
  }
}); 