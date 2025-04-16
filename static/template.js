// JS Template False Positive
// This file contains raw template tokens that look like injection points
// but are never evaluated server-side.

var user = '<% USERNAME %>';
// The above is just static text, not a real template engine.
