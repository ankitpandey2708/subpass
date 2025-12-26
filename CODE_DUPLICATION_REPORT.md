# Code Duplication Analysis Report

## Executive Summary
This report identifies code duplication patterns found in the SUBPASS subdomain reconnaissance codebase. Multiple instances of duplicated logic have been found that could be refactored to improve maintainability and reduce code size.

---

## 1. URL/Domain Parsing Logic Duplication

**Severity:** Medium
**Locations:**
- `app/api/subdomains/scan/route.ts:194-203` (fetchWaybackarchive)
- `app/api/subdomains/scan/route.ts:234-242` (fetchCommoncrawl)

**Duplicated Code:**
```typescript
let host = original;
if (host.includes('://')) {
    host = host.split('://')[1];
}
host = host.split('/')[0].split(':')[0].toLowerCase();
```

**Impact:** This host extraction logic appears in two separate fetch functions with identical implementation.

**Recommendation:** Extract this logic into a shared utility function in `subdomain-scanner.ts`:
```typescript
export function extractHostFromUrl(url: string): string {
    let host = url;
    if (host.includes('://')) {
        host = host.split('://')[1];
    }
    return host.split('/')[0].split(':')[0].toLowerCase();
}
```

---

## 2. Fetch Pattern Duplication

**Severity:** High
**Locations:** All 11 fetch functions in `app/api/subdomains/scan/route.ts`:
- fetchCrtsh (lines 23-51)
- fetchRapiddns (lines 54-80)
- fetchAlienvault (lines 83-106)
- fetchHackertarget (lines 109-135)
- fetchAnubis (lines 138-156)
- fetchThreatcrowd (lines 159-175)
- fetchWaybackarchive (lines 178-212)
- fetchCommoncrawl (lines 215-254)
- fetchCertspotter (lines 257-282)
- fetchSublist3rApi (lines 285-300)
- fetchBevigil (lines 303-318)

**Duplicated Pattern:**
Every function follows this identical structure:
```typescript
async function fetchXXX(domain: string): Promise<Set<string>> {
    const url = `...`;
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(TIMEOUT),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();
        // ... source-specific parsing logic
    } catch {
        return new Set();
    }
}
```

**Impact:**
- ~330 lines of repetitive boilerplate code
- Inconsistent timeout values (30000, 40000, 60000)
- Error handling duplicated 11 times

**Recommendation:** Create a generic fetch wrapper:
```typescript
async function fetchSource<T>(
    url: string,
    timeout: number,
    parser: (response: Response) => Promise<Set<string>>
): Promise<Set<string>> {
    try {
        const response = await fetch(url, {
            headers: HEADERS,
            signal: AbortSignal.timeout(timeout),
            cache: 'no-store'
        });
        if (!response.ok) return new Set();
        return await parser(response);
    } catch {
        return new Set();
    }
}
```

---

## 3. Domain Validation Regex Duplication

**Severity:** Medium
**Locations:**
- `app/lib/subdomain-scanner.ts:51` (isValidDomain function)
- `app/lib/subdomain-scanner.ts:65` (cleanSubdomain function)
- `app/lib/subdomain-scanner.ts:75` (processSubdomains function)

**Duplicated Code:**
```typescript
/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/
```

**Impact:** Same regex pattern hardcoded in 3 different locations. Changes need to be replicated manually.

**Recommendation:** Extract to a constant:
```typescript
export const DOMAIN_REGEX = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
```

---

## 4. Subdomain Filtering Logic Duplication

**Severity:** High
**Locations:** Repeated in 11 fetch functions in `app/api/subdomains/scan/route.ts`

**Duplicated Pattern:**
```typescript
// Pattern 1: Basic filtering (appears 8 times)
if (subdomain.endsWith(domain) && !subdomain.startsWith('*')) {
    subdomains.add(subdomain.toLowerCase());
}

// Pattern 2: With additional validation (appears 3 times)
.map(s => s.toLowerCase())
.filter(s => s.endsWith(domain) && !s.startsWith('*'))
```

**Examples:**
- Lines 41-43 (fetchCrtsh)
- Lines 72-74 (fetchRapiddns)
- Lines 98-100 (fetchAlienvault)
- Lines 126-128 (fetchHackertarget)
- Lines 150 (fetchAnubis)
- Lines 171 (fetchThreatcrowd)
- Lines 201-203 (fetchWaybackarchive)
- Lines 240-242 (fetchCommoncrawl)
- Lines 273-275 (fetchCertspotter)
- Lines 296 (fetchSublist3rApi)
- Lines 314 (fetchBevigil)

**Impact:** Same filtering logic copy-pasted 11 times across different functions.

**Recommendation:** Use the existing `cleanSubdomain()` utility or create a dedicated filter function:
```typescript
function filterValidSubdomains(
    subdomains: string[],
    baseDomain: string
): Set<string> {
    return new Set(
        subdomains
            .map(s => s.toLowerCase().trim())
            .filter(s => s.endsWith(baseDomain) && !s.startsWith('*'))
    );
}
```

---

## 5. User-Agent Header Duplication

**Severity:** Low
**Locations:**
- `app/lib/subdomain-scanner.ts:24` (HEADERS constant)
- `app/api/subdomains/status/route.ts:30` (inline in fetchWithoutSSLVerification)

**Duplicated Code:**
```typescript
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
```

**Impact:** User-Agent string duplicated in two files. Inconsistency risk if one is updated.

**Recommendation:** Import HEADERS from subdomain-scanner.ts into status/route.ts.

---

## 6. Error Response Pattern Duplication

**Severity:** Low
**Locations:**
- `app/api/subdomains/scan/route.ts:390-393`
- `app/api/subdomains/status/route.ts:121-127`

**Duplicated Pattern:**
```typescript
catch (error) {
    console.error('... error:', error);
    return NextResponse.json(
        { error: 'Failed to ...' },
        { status: 500 }
    );
}
```

**Impact:** Minor duplication of error handling pattern.

**Recommendation:** Consider creating a helper function for consistent error responses:
```typescript
function createErrorResponse(message: string, status = 500) {
    return NextResponse.json({ error: message }, { status });
}
```

---

## 7. Status Check Logic in Frontend

**Severity:** Low
**Locations:**
- `app/page.tsx:131-132` (calculating working/checked counts)

**Note:** This is minimal duplication but could be extracted if more complex calculations are needed.

---

## Summary Statistics

| Category | Instances | Lines of Duplicated Code (est.) |
|----------|-----------|----------------------------------|
| Fetch Pattern Duplication | 11 | ~330 lines |
| Subdomain Filtering | 11 | ~50 lines |
| Domain Validation Regex | 3 | ~3 lines |
| URL Parsing Logic | 2 | ~8 lines |
| User-Agent Header | 2 | ~2 lines |
| Error Response Pattern | 2 | ~12 lines |
| **TOTAL** | **31** | **~405 lines** |

---

## Refactoring Priority

1. **High Priority:**
   - Fetch pattern duplication (Issue #2)
   - Subdomain filtering logic (Issue #4)

2. **Medium Priority:**
   - URL/domain parsing logic (Issue #1)
   - Domain validation regex (Issue #3)

3. **Low Priority:**
   - User-Agent header (Issue #5)
   - Error response pattern (Issue #6)

---

## Benefits of Refactoring

1. **Reduced Code Size:** Eliminate ~405 lines of duplicated code
2. **Improved Maintainability:** Single source of truth for common logic
3. **Consistency:** Unified behavior across all fetch functions
4. **Easier Testing:** Centralized utility functions are easier to unit test
5. **Bug Fixes:** Fix once, apply everywhere

---

## Next Steps

1. Create utility functions in `app/lib/subdomain-scanner.ts`
2. Refactor fetch functions to use shared utilities
3. Update imports in affected files
4. Add unit tests for new utility functions
5. Verify all functionality works as expected

---

*Report generated: 2025-12-26*
