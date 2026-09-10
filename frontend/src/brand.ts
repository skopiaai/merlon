/**
 * The product name, in one place.
 *
 * Renaming a product touches the UI, the page title, the docs, the container
 * names, the data directory and the environment variables. The last rename
 * missed two of those and broke startup, so the parts that *can* be defined
 * once are defined here.
 */
export const PRODUCT_NAME = "Merlon";
export const MAKER_NAME = "Skopia AI";

/** For <title>, and anywhere the two need to read as one string. */
export const FULL_NAME = `${PRODUCT_NAME} — by ${MAKER_NAME}`;
