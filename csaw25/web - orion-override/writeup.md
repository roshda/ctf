## CSAW 2025 Quals – web/orion override

published: 2025-09-13

This weekend, I played CSAW 2025 Quals with [Psi Beta Rho at UCLA](https://pbr.acmcyber.com/) (we qualified yay). I solved a web challenge called orion-override.

The challenge gives you a login page and, if you view source, credentials are in an HTML comment. For some reason logging in with those drops you on `/dashboard?admin=false`, where you get a user dashboard with a bunch of buttons that don’t work.

Changing `admin=false` to `admin=true` in the URL doesn’t do anything. Adding `admin=true` to the login POST doesn’t do anything either. The session cookie is a signed Express session ID, which is not something you can really tamper with. 

### Solve process

At that point I opened Burp and started looking at the `/dashboard` request directly.

The normal request after login looks like:

```
GET /dashboard?admin=false
```

I tried the obvious stuff first (`admin=true`, random parameters, guessing APIs) and none of it worked. What ended up working was

```
GET /dashboard?admin=false&admin=true
```

which is HTTP parameter pollution. That immediately returned the admin dashboard.


### Explanation

Express parses duplicate query parameters into arrays. With the app’s configuration, the request above turns into something like:

```js
req.query.admin = ["false", "true"]
```

The backend then does two different authorization checks depending on whether `admin` is an array or not. In the array case, it only checks the last value and completely skips checking whether the session is actually an admin.

This means

* `?admin=true` requires `req.session.isAdmin`
* `?admin=false&admin=true` means no admin session check at all

As long as `"true"` is last, you get admin access.

### Flag


```
csawctf{h7tpp0llut10n_0r10n_z8y7x6w5v4u3}
```

Interesting Express feature! Thanks CSAW for the interesting challenges as always!!!
