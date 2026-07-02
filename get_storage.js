// Inject this into browser to test what it sees
try {
  console.log("Cookies:", document.cookie);
  console.log("LocalStorage length:", window.localStorage ? window.localStorage.length : 'none');
  console.log("SessionStorage length:", window.sessionStorage ? window.sessionStorage.length : 'none');
} catch(e) {
  console.log("Error:", e.message);
}
