### **Description**  

**Mkrul** is a rule compiler for **Application Layer DPI** (content filtering) system. It transforms human-readable JSON rules into optimized binary format for [Tantal Web Filter](https://hub.docker.com/r/tantalsec/tantal-wf). The web filter is an [original library-based solution](https://hub.docker.com/r/tantalsec/tantal-wf) designed to integrate with nginx and its forks.

### **Usage**  
Converts JSON web filtering rules into a binary format. Takes `endpoints.json` (default) with paths, methods, and rules, outputs optimized `sentinels.bin`.  

Flags:  
- `-i` – input JSON file  
- `-o` – output binary file  
- `-d` – debug mode  

Example:  
```sh
./mkrul -i rules.json -o rules.bin
```

or without compilation:
```sh
go run mkrul.go -i rules.json -o rules.bin
```

### **Rules scheme**  

#### **1. Format Structure**  
```json
[
  {
    "path": "/api/*",
    "method": "POST",
    "rules": [
      "conditions : action",
      "action"
    ]
  }
]
```

#### **2. Key Fields**  
| Field    | Description                                                                 | Examples                     |
|---------|--------------------------------------------------------------------------|-----------------------------|
| `path`  | Path with globbing (`*` only for full segments)                        | `"/"`, `"/data/*"`          |
| `method`| HTTP method (`*` or `""` for all methods)                               | `"GET"`, `"*"`              |
| `rules` | List of rules (checked in order, the first match determines the action) | `["$ctx == 'json' : block"]` |

#### **3. Supported Contexts (`$ctx`)**  
Available data types (can be combined with `|`):  
- `headers` – HTTP headers as key/value map
- `urlenc` – URL-encoded parameters as key/value map
- `base64` / `base64_url` – Base64-encoded data as string value 
- `cookie` – Cookies as key/value map
- `json` / `json_obj` / `json_array` – JSON data (json as supertype), json_obj as key/value map, json_array as array of string values
- `path` – URL path components as array of string values
- `http` – HTTP data as key/value map where predefined key is the part name of http packet and value is the string value view (if needed, depends on parser)
- `auth_header` – Authorization header as key/value single map
- `jwt` – JWT tokens as key/value map with predefined keys and typed json values (signature does not parse)

Available http keys (example: GET http://somesec.com/a/b/c?d=1&e=2)

- `method` – HTTP method (GET)
- `scheme` – HTTP scheme (http)  
- `uri` – URI (http://somesec.com/a/b/c?d=1&e=2)
- `path` – path (/a/b/c)  
- `query` – query part (d=1&e=2)   
- `headers` – headers  
- `body` – body

Available jwt keys

- `header` – jwt header
- `payload` – jwt payload 

#### **4. Rule Format**  
```
[conditions] : [action]
```
Where:  
- **Conditions**: `$field operator value`  
- **Action**: `block` or `pass`  

#### **5. Operators and Values**  
| Component  | Description                                                                 | Examples                          |
|------------|--------------------------------------------------------------------------|----------------------------------|
| `$field`   | `ctx` (data type), `key` (key), `val` (value)                       | `$ctx`, `$key`                   |
| `operator` | `==` (equals), `!=` (not equals)                                  | `==`, `!=`                       |
| `value`    | String (`'text'`) or regex (`/pattern/`). For arrays, index as string. | `'admin'`, `/^[0-9]+$/`, `'0'` |

The regex implementation follows the [YandexPIRE](https://github.com/yandex/pire) library's syntax rules. 

#### **6. Special Features**  
1. **Multi-contexts**:  
   ```json
   "$ctx == 'json_obj|json_array' $key == 'id' : block"
   ```  

2. **Array Handling**:  
   ```json
   // Check the first array element  
   "$ctx == 'json_array' $key == '0' $val == 'root' : block"  
   
   // Regex for indices  
   "$ctx == 'json_array' $key == /^[1-5]$/ : block"  
   ```  

3. **Escaping**:  
   ```json
   "$val == '\\\\\"quote\\\\\"'"  // → checks for \"quote\"  
   ```  

#### **7. Rule Examples**  
**Blocking by JSON:**  
```json
{
  "path": "/api/user",
  "method": "POST",
  "rules": [
    "$ctx == 'json_obj' $key == 'role' $val == 'admin' : block",
    "pass"
  ]
}
```  

**Array Filtering:**  
```json
{
  "path": "/data/*",
  "method": "PUT",
  "rules": [
    "$ctx == 'json_array|json_obj' $key == '0' $val == 'delete' : pass",
    "$ctx == 'http' $key == 'body' : $ctx == 'json_obj' $key == 'status' $val == 'error' : pass",
    "$ctx == 'headers' $key == 'Host' $val == '127.0.0.1' : pass", 
    "block"
  ]
}
```  

**Complex Check:**  
```json
{
  "path": "/",
  "method": "*",
  "rules": [
    "$ctx == 'headers|cookie' $key == 'token' $val == /^dev_/ : block",
    "$ctx == 'jwt' : $ctx == 'json_obj' $key == 'iss' $val != 'trusted' : block",
    "pass"
  ]
}
```  

#### **8. Important Rules**  
1. Priority is determined by order in `rules` (first match wins).  
2. `*` in `path` works only for full segments (`/api/*` ✔️, `/api/*.json` ❌).  
3. For arrays, indices must be strings (`'0'`, `'1'`) or regexp.  
4. Escape special characters with double backslashes (`\\` → `\\\\`). The JSON package in Golang unescapes strings before internal processing.

This format enables flexible HTTP request filtering with support for complex conditions, including JSON, headers, JWT, and other data types.  

If you have any questions, please contact us at [team@tantalsec.com](mailto:team@tantalsec.com).

---  
