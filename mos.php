<?php
/**
 * MOS - My Operating System
 * A web-based operating system environment in a single file
 * 
 * Version: 1.0.0-alpha
 * Build Date: 2025-07-04
 * 
 * This file provides both the backend services and frontend interface
 * for the MOS operating system environment.
 */

// Start session for user authentication
session_start();

// Configuration
$config = [
    'system' => [
        'name' => 'MOS',
        'version' => '1.0.0-alpha',
        'build' => '20250704.1',
        'debug' => true
    ],
    'security' => [
        'admin_users' => ['admin', 'developer'],
        'sandbox_enabled' => true,
        'sandbox_memory_limit' => '64M',
        'sandbox_time_limit' => 5, // seconds
    ],
    'filesystem' => [
        'root_dir' => __DIR__ . '/mos_files',
        'user_dir' => __DIR__ . '/mos_files/users',
        'apps_dir' => __DIR__ . '/mos_files/apps',
        'system_dir' => __DIR__ . '/mos_files/system',
        'temp_dir' => __DIR__ . '/mos_files/temp'
    ],
    'ui' => [
        'theme' => 'dark',
        'animations' => true,
        'fontSize' => 'medium',
        'language' => 'en'
    ]
];

// Ensure required directories exist
foreach ($config['filesystem'] as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
    }
}

// API handling
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    // API authentication check (except for auth API)
    if ($_GET['api'] !== 'auth' && !isAuthenticated()) {
        echo json_encode(['success' => false, 'message' => 'Authentication required']);
        exit;
    }
    
    $result = ['success' => false, 'message' => 'Unknown API endpoint'];
    
    switch ($_GET['api']) {
        case 'auth':
            $result = handleAuthAPI();
            break;
            
        case 'filesystem':
            $result = handleFileSystemAPI();
            break;
            
        case 'apps':
            $result = handleAppsAPI();
            break;
            
        case 'users':
            $result = handleUsersAPI();
            break;
            
        case 'system':
            $result = handleSystemAPI();
            break;
            
        case 'sandbox':
            $result = handleSandboxAPI();
            break;
    }
    
    echo json_encode($result);
    exit;
}

// File serving (for app resources, user files, etc.)
if (isset($_GET['file'])) {
    serveFile($_GET['file']);
    exit;
}

// Helper Functions

/**
 * Check if the user is authenticated
 */
function isAuthenticated() {
    return isset($_SESSION['user']);
}

/**
 * Get current user information
 */
function getCurrentUser() {
    return $_SESSION['user'] ?? null;
}

/**
 * Check if current user is an admin
 */
function isAdmin() {
    global $config;
    $user = getCurrentUser();
    return $user && in_array($user['username'], $config['security']['admin_users']);
}

/**
 * Handle authentication API requests
 */
function handleAuthAPI() {
    $method = $_POST['method'] ?? '';
    $params = $_POST['params'] ?? [];
    
    switch ($method) {
        case 'login':
            // In a real system, you would validate credentials against a database
            // For this demo, we'll accept a few hardcoded users
            if (isset($params['username']) && isset($params['password'])) {
                // Demo users (in a real system, use proper password hashing)
                $validUsers = [
                    'admin' => 'admin123',
                    'developer' => 'dev123',
                    'user' => 'user123'
                ];
                
                if (isset($validUsers[$params['username']]) && 
                    $validUsers[$params['username']] === $params['password']) {
                    
                    $user = [
                        'username' => $params['username'],
                        'name' => ucfirst($params['username']),
                        'role' => in_array($params['username'], ['admin', 'developer']) ? 'admin' : 'user',
                        'lastLogin' => date('Y-m-d H:i:s')
                    ];
                    
                    $_SESSION['user'] = $user;
                    
                    return [
                        'success' => true,
                        'data' => [
                            'user' => $user,
                            'permissions' => getUserPermissions($user['username'])
                        ]
                    ];
                }
                
                return [
                    'success' => false,
                    'message' => 'Invalid username or password'
                ];
            }
            break;
            
        case 'logout':
            unset($_SESSION['user']);
            return ['success' => true, 'message' => 'Logged out successfully'];
            
        case 'validateToken':
            $user = getCurrentUser();
            if ($user) {
                return [
                    'success' => true,
                    'data' => [
                        'valid' => true,
                        'user' => $user,
                        'permissions' => getUserPermissions($user['username'])
                    ]
                ];
            }
            return ['success' => true, 'data' => ['valid' => false]];
            
        case 'getCurrentUser':
            $user = getCurrentUser();
            if ($user) {
                return ['success' => true, 'data' => $user];
            }
            return ['success' => false, 'message' => 'Not authenticated'];
    }
    
    return ['success' => false, 'message' => 'Invalid method'];
}

/**
 * Get permissions for a user
 */
function getUserPermissions($username) {
    // In a real system, this would come from a database
    $permissions = [
        'app.launch.*', // Allow launching any app
        'filesystem.read.*', // Allow reading any file
    ];
    
    // Admins get additional permissions
    if (in_array($username, ['admin', 'developer'])) {
        $permissions = array_merge($permissions, [
            'filesystem.write.*', // Allow writing any file
            'filesystem.delete.*', // Allow deleting any file
            'system.config.*',     // Allow changing system config
            'system.admin.*',      // Allow all admin actions
            'sandbox.execute.*'    // Allow executing sandboxed code
        ]);
    } else {
        // Regular users get more limited permissions
        $permissions = array_merge($permissions, [
            'filesystem.write.user.*', // Allow writing to user directory
            'filesystem.delete.user.*', // Allow deleting from user directory
            'sandbox.execute.user'      // Allow executing user sandboxed code
        ]);
    }
    
    return $permissions;
}

/**
 * Handle filesystem API requests
 */
function handleFileSystemAPI() {
    global $config;
    $method = $_POST['method'] ?? '';
    $params = $_POST['params'] ?? [];
    
    // Convert virtual path to real path
    function resolvePath($virtualPath) {
        global $config;
        
        // Normalize the path (remove ../, multiple slashes, etc.)
        $virtualPath = '/' . trim($virtualPath, '/');
        $parts = array_filter(explode('/', $virtualPath), 'strlen');
        $absolutes = [];
        
        foreach ($parts as $part) {
            if ($part === '.') {
                continue;
            }
            
            if ($part === '..') {
                array_pop($absolutes);
            } else {
                $absolutes[] = $part;
            }
        }
        
        $normalizedPath = '/' . implode('/', $absolutes);
        
        // Map to real paths
        if (strpos($normalizedPath, '/users/') === 0) {
            return $config['filesystem']['user_dir'] . substr($normalizedPath, 6);
        } elseif (strpos($normalizedPath, '/apps/') === 0) {
            return $config['filesystem']['apps_dir'] . substr($normalizedPath, 5);
        } elseif (strpos($normalizedPath, '/system/') === 0) {
            return $config['filesystem']['system_dir'] . substr($normalizedPath, 7);
        } elseif (strpos($normalizedPath, '/temp/') === 0) {
            return $config['filesystem']['temp_dir'] . substr($normalizedPath, 5);
        } else {
            return $config['filesystem']['root_dir'] . $normalizedPath;
        }
    }
    
    // Security check - only admins can access files outside their user directory
    function canAccessPath($virtualPath, $writeAccess = false) {
        $user = getCurrentUser();
        
        // Admins can access anything
        if (isAdmin()) {
            return true;
        }
        
        // Users can read from the apps and system directories
        if (!$writeAccess && (strpos($virtualPath, '/apps/') === 0 || strpos($virtualPath, '/system/') === 0)) {
            return true;
        }
        
        // Users can only access their own user directory for writing
        if (strpos($virtualPath, '/users/' . $user['username']) === 0) {
            return true;
        }
        
        return false;
    }
    
    switch ($method) {
        case 'readFile':
            if (isset($params['path'])) {
                $virtualPath = $params['path'];
                
                if (!canAccessPath($virtualPath)) {
                    return ['success' => false, 'message' => 'Access denied'];
                }
                
                $realPath = resolvePath($virtualPath);
                
                if (file_exists($realPath) && is_file($realPath)) {
                    $content = file_get_contents($realPath);
                    return [
                        'success' => true,
                        'data' => [
                            'content' => $content,
                            'size' => filesize($realPath),
                            'modified' => filemtime($realPath)
                        ]
                    ];
                }
                
                return ['success' => false, 'message' => 'File not found'];
            }
            break;
            
        case 'writeFile':
            if (isset($params['path']) && isset($params['content'])) {
                $virtualPath = $params['path'];
                
                if (!canAccessPath($virtualPath, true)) {
                    return ['success' => false, 'message' => 'Access denied'];
                }
                
                $realPath = resolvePath($virtualPath);
                $dir = dirname($realPath);
                
                if (!file_exists($dir)) {
                    mkdir($dir, 0755, true);
                }
                
                if (file_put_contents($realPath, $params['content']) !== false) {
                    return [
                        'success' => true,
                        'data' => [
                            'path' => $virtualPath,
                            'size' => filesize($realPath),
                            'modified' => filemtime($realPath)
                        ]
                    ];
                }
                
                return ['success' => false, 'message' => 'Failed to write file'];
            }
            break;
            
        case 'deleteFile':
            if (isset($params['path'])) {
                $virtualPath = $params['path'];
                
                if (!canAccessPath($virtualPath, true)) {
                    return ['success' => false, 'message' => 'Access denied'];
                }
                
                $realPath = resolvePath($virtualPath);
                
                if (file_exists($realPath) && is_file($realPath)) {
                    if (unlink($realPath)) {
                        return ['success' => true];
                    }
                    
                    return ['success' => false, 'message' => 'Failed to delete file'];
                }
                
                return ['success' => false, 'message' => 'File not found'];
            }
            break;
            
        case 'listDirectory':
            if (isset($params['path'])) {
                $virtualPath = $params['path'];
                
                if (!canAccessPath($virtualPath)) {
                    return ['success' => false, 'message' => 'Access denied'];
                }
                
                $realPath = resolvePath($virtualPath);
                
                if (file_exists($realPath) && is_dir($realPath)) {
                    $items = scandir($realPath);
                    $items = array_diff($items, ['.', '..']);
                    
                    $files = [];
                    $dirs = [];
                    
                    foreach ($items as $item) {
                        $fullPath = $realPath . '/' . $item;
                        $itemData = [
                            'name' => $item,
                            'path' => $virtualPath . '/' . $item,
                            'modified' => filemtime($fullPath)
                        ];
                        
                        if (is_file($fullPath)) {
                            $itemData['type'] = 'file';
                            $itemData['size'] = filesize($fullPath);
                            $itemData['extension'] = pathinfo($item, PATHINFO_EXTENSION);
                            $files[] = $itemData;
                        } else {
                            $itemData['type'] = 'directory';
                            $dirs[] = $itemData;
                        }
                    }
                    
                    // Sort directories first, then files
                    usort($dirs, function($a, $b) { return strcmp($a['name'], $b['name']); });
                    usort($files, function($a, $b) { return strcmp($a['name'], $b['name']); });
                    
                    return [
                        'success' => true,
                        'data' => array_merge($dirs, $files)
                    ];
                }
                
                return ['success' => false, 'message' => 'Directory not found'];
            }
            break;
            
        case 'createDirectory':
            if (isset($params['path'])) {
                $virtualPath = $params['path'];
                
                if (!canAccessPath($virtualPath, true)) {
                    return ['success' => false, 'message' => 'Access denied'];
                }
                
                $realPath = resolvePath($virtualPath);
                
                if (!file_exists($realPath)) {
                    if (mkdir($realPath, 0755, true)) {
                        return ['success' => true];
                    }
                    
                    return ['success' => false, 'message' => 'Failed to create directory'];
                }
                
                return ['success' => false, 'message' => 'Directory already exists'];
            }
            break;
    }
    
    return ['success' => false, 'message' => 'Invalid method or parameters'];
}

/**
 * Handle apps API requests
 */
function handleAppsAPI() {
    $method = $_POST['method'] ?? '';
    $params = $_POST['params'] ?? [];
    
    switch ($method) {
        case 'getAppInfo':
            if (isset($params['appId'])) {
                $appId = $params['appId'];
                
                // In a real system, this would come from a database or app manifest files
                $apps = [
                    'files' => [
                        'id' => 'files',
                        'title' => 'File Manager',
                        'description' => 'Browse and manage files',
                        'icon' => '📁',
                        'version' => '1.0.0',
                        'author' => 'MOS Team',
                        'permissions' => ['filesystem.read.*', 'filesystem.write.user.*'],
                        'main' => 'apps/files/main.js',
                        'window' => [
                            'width' => 800,
                            'height' => 600,
                            'resizable' => true
                        ]
                    ],
                    'terminal' => [
                        'id' => 'terminal',
                        'title' => 'Terminal',
                        'description' => 'Command-line interface',
                        'icon' => '💻',
                        'version' => '1.0.0',
                        'author' => 'MOS Team',
                        'permissions' => ['filesystem.read.*', 'filesystem.write.user.*', 'process.exec'],
                        'main' => 'apps/terminal/main.js',
                        'window' => [
                            'width' => 700,
                            'height' => 500,
                            'resizable' => true
                        ]
                    ],
                    'editor' => [
                        'id' => 'editor',
                        'title' => 'Code Editor',
                        'description' => 'Edit text and code files',
                        'icon' => '📝',
                        'version' => '1.0.0',
                        'author' => 'MOS Team',
                        'permissions' => ['filesystem.read.*', 'filesystem.write.user.*'],
                        'main' => 'apps/editor/main.js',
                        'window' => [
                            'width' => 900,
                            'height' => 700,
                            'resizable' => true
                        ]
                    ],
                    'settings' => [
                        'id' => 'settings',
                        'title' => 'Settings',
                        'description' => 'Configure system settings',
                        'icon' => '⚙️',
                        'version' => '1.0.0',
                        'author' => 'MOS Team',
                        'permissions' => ['system.config.read', 'system.config.write'],
                        'main' => 'apps/settings/main.js',
                        'window' => [
                            'width' => 800,
                            'height' => 600,
                            'resizable' => true
                        ]
                    ]
                ];
                
                if (isset($apps[$appId])) {
                    return ['success' => true, 'data' => $apps[$appId]];
                }
                
                return ['success' => false, 'message' => 'Application not found'];
            }
            break;
            
        case 'listApps':
            // In a real system, this would come from a database or app manifest files
            $apps = [
                [
                    'id' => 'files',
                    'title' => 'File Manager',
                    'description' => 'Browse and manage files',
                    'icon' => '📁',
                    'category' => 'System'
                ],
                [
                    'id' => 'terminal',
                    'title' => 'Terminal',
                    'description' => 'Command-line interface',
                    'icon' => '💻',
                    'category' => 'System'
                ],
                [
                    'id' => 'editor',
                    'title' => 'Code Editor',
                    'description' => 'Edit text and code files',
                    'icon' => '📝',
                    'category' => 'Development'
                ],
                [
                    'id' => 'settings',
                    'title' => 'Settings',
                    'description' => 'Configure system settings',
                    'icon' => '⚙️',
                    'category' => 'System'
                ]
            ];
            
            return ['success' => true, 'data' => $apps];
    }
    
    return ['success' => false, 'message' => 'Invalid method or parameters'];
}

/**
 * Handle users API requests
 */
function handleUsersAPI() {
    $method = $_POST['method'] ?? '';
    $params = $_POST['params'] ?? [];
    
    // Only admins can access user data
    if (!isAdmin() && $method !== 'getCurrentUser') {
        return ['success' => false, 'message' => 'Access denied'];
    }
    
    switch ($method) {
        case 'getCurrentUser':
            $user = getCurrentUser();
            if ($user) {
                return ['success' => true, 'data' => $user];
            }
            return ['success' => false, 'message' => 'Not authenticated'];
            
        case 'listUsers':
            // In a real system, this would come from a database
            $users = [
                [
                    'username' => 'admin',
                    'name' => 'Administrator',
                    'role' => 'admin',
                    'lastLogin' => '2025-07-04 08:30:00'
                ],
                [
                    'username' => 'developer',
                    'name' => 'Developer',
                    'role' => 'admin',
                    'lastLogin' => '2025-07-03 16:45:22'
                ],
                [
                    'username' => 'user',
                    'name' => 'Regular User',
                    'role' => 'user',
                    'lastLogin' => '2025-07-02 09:12:37'
                ]
            ];
            
            return ['success' => true, 'data' => $users];
    }
    
    return ['success' => false, 'message' => 'Invalid method or parameters'];
}

/**
 * Handle system API requests
 */
function handleSystemAPI() {
    global $config;
    $method = $_POST['method'] ?? '';
    $params = $_POST['params'] ?? [];
    
    switch ($method) {
        case 'getSystemInfo':
            return [
                'success' => true,
                'data' => [
                    'name' => $config['system']['name'],
                    'version' => $config['system']['version'],
                    'build' => $config['system']['build'],
                    'php_version' => PHP_VERSION,
                    'server' => $_SERVER['SERVER_SOFTWARE'],
                    'debug_mode' => $config['system']['debug'],
                    'uptime' => time() - $_SERVER['REQUEST_TIME_FLOAT']
                ]
            ];
            
        case 'updateConfig':
            // Only admins can update config
            if (!isAdmin()) {
                return ['success' => false, 'message' => 'Access denied'];
            }
            
            if (isset($params['key']) && isset($params['value'])) {
                $key = $params['key'];
                $value = $params['value'];
                
                // Update config (in a real system, would save to a file/database)
                $keys = explode('.', $key);
                $ref = &$config;
                
                foreach ($keys as $k) {
                    if (!isset($ref[$k])) {
                        return ['success' => false, 'message' => 'Invalid config key'];
                    }
                    $ref = &$ref[$k];
                }
                
                $ref = $value;
                
                return ['success' => true, 'message' => 'Configuration updated'];
            }
            break;
    }
    
    return ['success' => false, 'message' => 'Invalid method or parameters'];
}

/**
 * Handle sandbox API requests
 */
function handleSandboxAPI() {
    global $config;
    $method = $_POST['method'] ?? '';
    $params = $_POST['params'] ?? [];
    
    // Only admins or users with specific permissions can execute sandboxed code
    $user = getCurrentUser();
    $allowedSandbox = isAdmin() || (isset($params['context']) && $params['context'] === 'user');
    
    if (!$allowedSandbox) {
        return ['success' => false, 'message' => 'Access denied for sandbox execution'];
    }
    
    switch ($method) {
        case 'execute':
            if (isset($params['code']) && is_string($params['code'])) {
                $code = $params['code'];
                $context = $params['context'] ?? 'default';
                
                // Set strict limits for sandboxed code
                $memoryLimit = $config['security']['sandbox_memory_limit'];
                $timeLimit = $config['security']['sandbox_time_limit'];
                
                // Create a temporary file to execute
                $tempFile = $config['filesystem']['temp_dir'] . '/sandbox_' . uniqid() . '.php';
                
                // Create a wrapper that catches errors and limits execution
                $wrapper = <<<EOT
<?php
// Set resource limits
ini_set('memory_limit', '$memoryLimit');
set_time_limit($timeLimit);

// Capture output
ob_start();

// Disable dangerous functions
function disabled_function() {
    return "Function disabled in sandbox";
}

// Sandbox security - disable dangerous functions
function system() { return disabled_function(); }
function exec() { return disabled_function(); }
function shell_exec() { return disabled_function(); }
function passthru() { return disabled_function(); }
function proc_open() { return disabled_function(); }
function popen() { return disabled_function(); }
function curl_exec() { return disabled_function(); }
function fsockopen() { return disabled_function(); }
function file_put_contents() { return disabled_function(); }
function file_get_contents() { return disabled_function(); }
function fopen() { return disabled_function(); }
function include() { return disabled_function(); }
function include_once() { return disabled_function(); }
function require() { return disabled_function(); }
function require_once() { return disabled_function(); }

// Define safe context variables if needed
\$context = '$context';
\$user = '{$user['username']}';

// Run the user code in a try-catch block
try {
    // User code starts here
    $code
    // User code ends here
} catch (Throwable \$e) {
    echo "Error: " . \$e->getMessage();
}

// Get and clean output
\$output = ob_get_clean();
echo json_encode(['output' => \$output]);
EOT;
                
                // Write the wrapper to the temp file
                file_put_contents($tempFile, $wrapper);
                
                // Execute in a separate process
                $descriptorspec = [
                    0 => ["pipe", "r"],  // stdin
                    1 => ["pipe", "w"],  // stdout
                    2 => ["pipe", "w"]   // stderr
                ];
                
                $process = proc_open('php ' . $tempFile, $descriptorspec, $pipes);
                
                if (is_resource($process)) {
                    // Close stdin
                    fclose($pipes[0]);
                    
                    // Get output
                    $output = stream_get_contents($pipes[1]);
                    $errors = stream_get_contents($pipes[2]);
                    
                    // Close pipes
                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    
                    // Close process
                    $exitCode = proc_close($process);
                    
                    // Clean up temp file
                    @unlink($tempFile);
                    
                    // Parse the output (should be JSON)
                    $result = json_decode($output, true);
                    
                    if ($result !== null) {
                        return [
                            'success' => true,
                            'data' => [
                                'output' => $result['output'],
                                'errors' => $errors,
                                'exitCode' => $exitCode
                            ]
                        ];
                    }
                    
                    return [
                        'success' => false,
                        'message' => 'Failed to parse sandbox output',
                        'data' => [
                            'raw' => $output,
                            'errors' => $errors,
                            'exitCode' => $exitCode
                        ]
                    ];
                }
                
                return ['success' => false, 'message' => 'Failed to create sandbox process'];
            }
            break;
    }
    
    return ['success' => false, 'message' => 'Invalid method or parameters'];
}

/**
 * Serve a file from the filesystem
 */
function serveFile($path) {
    global $config;
    
    // Convert virtual path to real path
    function resolveFilePath($virtualPath) {
        global $config;
        
        $virtualPath = '/' . trim($virtualPath, '/');
        
        if (strpos($virtualPath, '/users/') === 0) {
            return $config['filesystem']['user_dir'] . substr($virtualPath, 6);
        } elseif (strpos($virtualPath, '/apps/') === 0) {
            return $config['filesystem']['apps_dir'] . substr($virtualPath, 5);
        } elseif (strpos($virtualPath, '/system/') === 0) {
            return $config['filesystem']['system_dir'] . substr($virtualPath, 7);
        } elseif (strpos($virtualPath, '/temp/') === 0) {
            return $config['filesystem']['temp_dir'] . substr($virtualPath, 5);
        } else {
            return $config['filesystem']['root_dir'] . $virtualPath;
        }
    }
    
    // Security check
    if (!isAuthenticated()) {
        header('HTTP/1.1 403 Forbidden');
        echo 'Access denied';
        exit;
    }
    
    $realPath = resolveFilePath($path);
    
    if (file_exists($realPath) && is_file($realPath)) {
        // Check access permissions
        $canAccess = isAdmin();
        
        if (!$canAccess) {
            $user = getCurrentUser();
            
            // Users can read from apps and system directories
            if (strpos($path, '/apps/') === 0 || strpos($path, '/system/') === 0) {
                $canAccess = true;
            }
            
            // Users can read from their own user directory
            if (strpos($path, '/users/' . $user['username']) === 0) {
                $canAccess = true;
            }
        }
        
        if (!$canAccess) {
            header('HTTP/1.1 403 Forbidden');
            echo 'Access denied';
            exit;
        }
        
        // Determine MIME type
        $mimeTypes = [
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'html' => 'text/html',
            'htm' => 'text/html',
            'txt' => 'text/plain',
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'svg' => 'image/svg+xml',
            'pdf' => 'application/pdf'
        ];
        
        $ext = strtolower(pathinfo($realPath, PATHINFO_EXTENSION));
        $contentType = $mimeTypes[$ext] ?? 'application/octet-stream';
        
        header('Content-Type: ' . $contentType);
        header('Content-Length: ' . filesize($realPath));
        
        // Output file contents
        readfile($realPath);
        exit;
    }
    
    // File not found
    header('HTTP/1.1 404 Not Found');
    echo 'File not found';
    exit;
}

// Initialize default files if they don't exist
function initializeSystemFiles() {
    global $config;
    
    // Create MOS logo SVG
    $logoPath = $config['filesystem']['system_dir'] . '/logo.svg';
    if (!file_exists($logoPath)) {
        $logoSvg = <<<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">
  <defs>
    <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#3f51b5" />
      <stop offset="100%" stop-color="#ff4081" />
    </linearGradient>
  </defs>
  <rect x="20" y="20" width="160" height="160" rx="15" fill="#252525" stroke="url(#logoGradient)" stroke-width="5" />
  <path d="M50 70 L50 130 L70 130 L70 70 Z" fill="url(#logoGradient)" />
  <path d="M85 70 C105 70, 125 70, 145 70 C145 90, 145 110, 145 130 C125 130, 105 130, 85 130 Z" fill="url(#logoGradient)" />
  <path d="M85 100 L130 100" stroke="#252525" stroke-width="10" />
</svg>
SVG;
        file_put_contents($logoPath, $logoSvg);
    }
    
    // Create system.json config file
    $systemConfigPath = $config['filesystem']['system_dir'] . '/system.json';
    if (!file_exists($systemConfigPath)) {
        $systemConfig = json_encode($config, JSON_PRETTY_PRINT);
        file_put_contents($systemConfigPath, $systemConfig);
    }
    
    // Create a README file for users
    $readmePath = $config['filesystem']['root_dir'] . '/README.txt';
    if (!file_exists($readmePath)) {
        $readme = <<<TXT
Welcome to MOS - My Operating System

This is a web-based operating system environment that provides:
- A desktop interface
- Application management
- File management
- User accounts and security
- Sandboxed code execution

To get started, log in with one of these demo accounts:
- admin / admin123 (Administrator)
- developer / dev123 (Developer)
- user / user123 (Regular user)

Enjoy exploring MOS!
TXT;
        file_put_contents($readmePath, $readme);
    }

    // Create themes directory and default theme files
    $themesDir = $config['filesystem']['system_dir'] . '/themes';
    if (!file_exists($themesDir)) {
        mkdir($themesDir, 0755, true);
    }

    $defaultThemes = [
        'dark' => "/* Default dark theme */",
        'light' => "/* Default light theme */",
        'blue' => "/* Default blue theme */"
    ];

    foreach ($defaultThemes as $themeName => $content) {
        $themePath = "$themesDir/{$themeName}.css";
        if (!file_exists($themePath)) {
            file_put_contents($themePath, $content);
        }
    }
}

// Initialize system files
initializeSystemFiles();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="description" content="MOS - My Operating System">
    <meta name="theme-color" content="#1e1e1e">
    <link id="theme-stylesheet" rel="stylesheet" href="mos.php?file=/system/themes/dark.css">
    <title>MOS - My Operating System</title>
    
    <!-- Inline Styles -->
    <style>
        /* Reset and Base Styles */
        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        html, body {
            height: 100%;
            width: 100%;
            overflow: hidden;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 16px;
            line-height: 1.5;
            background-color: #1e1e1e;
            color: #f0f0f0;
        }
        
        /* Splash Screen */
        .mos-splash-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: #1e1e1e;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            transition: opacity 0.5s ease-in-out;
        }
        
        .mos-splash-screen.fade-out {
            opacity: 0;
        }
        
        #splash-logo {
            width: 150px;
            height: 150px;
            margin-bottom: 40px;
        }
        
        .mos-loading-indicator {
            width: 300px;
            text-align: center;
        }
        
        .mos-loading-bar {
            width: 100%;
            height: 6px;
            background-color: #333;
            border-radius: 3px;
            overflow: hidden;
            margin-bottom: 10px;
        }
        
        .mos-loading-progress {
            height: 100%;
            width: 0;
            background: linear-gradient(to right, #3f51b5, #ff4081);
            border-radius: 3px;
            transition: width 0.3s ease-out;
        }
        
        .mos-loading-status {
            font-size: 14px;
            color: #ccc;
        }
        
        /* Login Screen */
        .mos-login-screen {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: #1e1e1e;
            background-image: radial-gradient(circle at center, #2c3e50 0%, #1e1e1e 100%);
            z-index: 9998;
            opacity: 0;
            transition: opacity 0.5s ease-in-out;
        }
        
        .mos-login-screen.show {
            display: flex;
            justify-content: center;
            align-items: center;
            opacity: 1;
        }
        
        .mos-login-container {
            width: 360px;
            padding: 30px;
            background-color: rgba(30, 30, 30, 0.8);
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
        }
        
        .mos-login-logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .mos-login-logo img {
            width: 80px;
            height: 80px;
        }
        
        .mos-login-heading {
            text-align: center;
            font-size: 24px;
            font-weight: 400;
            color: #f0f0f0;
            margin-bottom: 30px;
        }
        
        .mos-login-form {
            display: flex;
            flex-direction: column;
        }
        
        .mos-login-input {
            position: relative;
            margin-bottom: 20px;
        }
        
        .mos-login-input input {
            width: 100%;
            padding: 10px 15px;
            font-size: 16px;
            background-color: rgba(255, 255, 255, 0.1);
            color: #f0f0f0;
            border: none;
            border-radius: 4px;
            outline: none;
        }
        
        .mos-login-input input:focus {
            background-color: rgba(255, 255, 255, 0.15);
            box-shadow: 0 0 0 2px rgba(63, 81, 181, 0.5);
        }
        
        .mos-login-button {
            padding: 12px;
            background: linear-gradient(to right, #3f51b5, #ff4081);
            color: white;
            font-size: 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: opacity 0.3s;
        }
        
        .mos-login-button:hover {
            opacity: 0.9;
        }
        
        .mos-login-error {
            color: #ff4081;
            font-size: 14px;
            text-align: center;
            margin-top: 15px;
            min-height: 20px;
        }
        
        /* Desktop Environment */
        .mos-desktop {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: #1e1e1e;
            background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect fill="%232c3e50" width="100" height="100"/><g fill-opacity="0.05" fill="%23ffffff"><path d="M0 0h50v50H0z"/><path d="M50 50h50v50H50z"/></g></svg>');
            background-size: 200px 200px;
            overflow: hidden;
            display: none;
            opacity: 0;
            transition: opacity 0.5s ease-in-out;
        }
        
        .mos-desktop.show {
            display: block;
            opacity: 1;
        }
        
        /* Workspace (where windows appear) */
        .mos-workspace {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 40px; /* Space for taskbar */
            overflow: hidden;
        }
        
        /* Taskbar */
        .mos-taskbar {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 40px;
            background-color: rgba(30, 30, 30, 0.9);
            border-top: 1px solid #333;
            display: flex;
            z-index: 1000;
        }
        
        .mos-start-button {
            width: 60px;
            height: 40px;
            display: flex;
            justify-content: center;
            align-items: center;
            background: none;
            border: none;
            color: #f0f0f0;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .mos-start-button:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        
        .mos-taskbar-items {
            flex: 1;
            display: flex;
            padding: 0 5px;
            overflow-x: auto;
            overflow-y: hidden;
        }
        
        .mos-taskbar-item {
            height: 40px;
            min-width: 160px;
            max-width: 200px;
            display: flex;
            align-items: center;
            padding: 0 10px;
            margin-right: 4px;
            background-color: rgba(60, 60, 60, 0.3);
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.2s;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .mos-taskbar-item:hover {
            background-color: rgba(80, 80, 80, 0.5);
        }
        
        .mos-taskbar-item.active {
            background-color: rgba(63, 81, 181, 0.3);
        }
        
        .mos-taskbar-item-icon {
            margin-right: 8px;
            font-size: 16px;
        }
        
        .mos-taskbar-item-title {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .mos-system-tray {
            display: flex;
            align-items: center;
            padding: 0 10px;
        }
        
        .mos-clock {
            font-size: 14px;
            min-width: 45px;
            text-align: center;
        }
        
        /* Start Menu */
        .mos-start-menu {
            position: absolute;
            bottom: 40px;
            left: 0;
            width: 300px;
            max-height: 0;
            background-color: rgba(30, 30, 30, 0.95);
            border-radius: 0 6px 0 0;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
            overflow: hidden;
            z-index: 1001;
            transition: max-height 0.3s ease-out;
        }
        
        .mos-start-menu.active {
            max-height: 600px;
        }
        
        .mos-user-info {
            padding: 20px;
            display: flex;
            align-items: center;
            background: linear-gradient(135deg, #3f51b5 0%, #ff4081 100%);
        }
        
        .mos-user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: #f0f0f0;
            margin-right: 15px;
        }
        
        .mos-user-name {
            font-size: 16px;
            font-weight: 500;
            color: white;
        }
        
        .mos-menu-items {
            padding: 10px 0;
        }
        
        .mos-menu-item {
            padding: 10px 20px;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .mos-menu-item:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        
        .mos-menu-separator {
            height: 1px;
            background-color: #444;
            margin: 10px 0;
        }
        
        /* Window System */
        .mos-window {
            position: absolute;
            background-color: #252525;
            border-radius: 6px;
            box-shadow: 0 5px 25px rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            min-width: 300px;
            min-height: 200px;
            z-index: 100;
            transition: transform 0.3s, opacity 0.3s;
        }
        
        .mos-window.minimized {
            transform: scale(0.7);
            opacity: 0;
            pointer-events: none;
        }
        
        .mos-window.maximized {
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            height: calc(100% - 40px) !important;
            border-radius: 0;
        }
        
        .mos-window-header {
            height: 32px;
            background-color: #333;
            border-radius: 6px 6px 0 0;
            display: flex;
            align-items: center;
            padding: 0 10px;
            cursor: move;
        }
        
        .mos-window-title {
            flex: 1;
            font-size: 14px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            user-select: none;
        }
        
        .mos-window-controls {
            display: flex;
        }
        
        .mos-window-controls button {
            width: 24px;
            height: 24px;
            background: none;
            border: none;
            color: #ccc;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
            margin-left: 2px;
        }
        
        .mos-window-controls button:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        
        .mos-window-minimize:hover {
            color: #ffeb3b;
        }
        
        .mos-window-maximize:hover {
            color: #4caf50;
        }
        
        .mos-window-close:hover {
            color: #f44336;
        }
        
        .mos-window-content {
            flex: 1;
            overflow: auto;
            position: relative;
        }
        
        .mos-app-loading {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: #252525;
            color: #ccc;
            font-size: 14px;
        }
        
        /* Contextual Menu */
        .mos-context-menu {
            position: absolute;
            min-width: 150px;
            background-color: #333;
            border-radius: 4px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            z-index: 2000;
            padding: 5px 0;
        }
        
        .mos-context-menu-item {
            padding: 8px 15px;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .mos-context-menu-item:hover {
            background-color: rgba(63, 81, 181, 0.3);
        }
        
        .mos-context-menu-separator {
            height: 1px;
            background-color: #444;
            margin: 5px 0;
        }
        
        /* Notifications */
        .mos-notification-container {
            position: fixed;
            bottom: 50px;
            right: 10px;
            width: 300px;
            z-index: 1500;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .mos-notification {
            background-color: #333;
            border-radius: 6px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            padding: 15px;
            transform: translateX(120%);
            transition: transform 0.3s ease-out;
        }
        
        .mos-notification.show {
            transform: translateX(0);
        }
        
        .mos-notification-title {
            font-weight: 500;
            margin-bottom: 5px;
        }
        
        .mos-notification-body {
            font-size: 14px;
            color: #ccc;
        }
        
        /* Modal Dialog */
        .mos-modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.6);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 2000;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s;
        }
        
        .mos-modal-backdrop.show {
            opacity: 1;
            pointer-events: auto;
        }
        
        .mos-modal {
            width: 400px;
            background-color: #333;
            border-radius: 6px;
            box-shadow: 0 5px 25px rgba(0, 0, 0, 0.5);
            transform: translateY(-20px);
            transition: transform 0.3s;
        }
        
        .mos-modal-backdrop.show .mos-modal {
            transform: translateY(0);
        }
        
        .mos-modal-header {
            padding: 15px;
            border-bottom: 1px solid #444;
        }
        
        .mos-modal-title {
            font-size: 18px;
            font-weight: 500;
        }
        
        .mos-modal-body {
            padding: 15px;
            max-height: 70vh;
            overflow-y: auto;
        }
        
        .mos-modal-footer {
            padding: 15px;
            border-top: 1px solid #444;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        
        .mos-button {
            padding: 8px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.2s;
        }
        
        .mos-button-primary {
            background-color: #3f51b5;
            color: white;
        }
        
        .mos-button-primary:hover {
            background-color: #303f9f;
        }
        
        .mos-button-secondary {
            background-color: #555;
            color: white;
        }
        
        .mos-button-secondary:hover {
            background-color: #444;
        }
        
        /* Error Screen */
        .mos-error-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: #1e1e1e;
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            display: none;
        }
        
        .mos-error-container {
            width: 500px;
            padding: 30px;
            background-color: #252525;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            text-align: center;
        }
        
        .mos-error-container h2 {
            color: #f44336;
            margin-bottom: 20px;
        }
        
        .mos-error-container p {
            margin-bottom: 25px;
            color: #ccc;
        }
        
        .mos-error-container pre {
            text-align: left;
            background-color: #333;
            padding: 15px;
            border-radius: 4px;
            overflow: auto;
            margin-bottom: 25px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        #mos-restart-button {
            padding: 10px 20px;
            background-color: #3f51b5;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.2s;
        }
        
        #mos-restart-button:hover {
            background-color: #303f9f;
        }
        
        /* App-specific styles */
        
        /* File Manager */
        .mos-file-manager {
            display: flex;
            flex-direction: column;
            height: 100%;
        }
        
        .mos-file-toolbar {
            display: flex;
            align-items: center;
            height: 40px;
            padding: 0 10px;
            background-color: #2a2a2a;
            border-bottom: 1px solid #444;
        }
        
        .mos-file-manager-content {
            display: flex;
            flex: 1;
        }
        
        .mos-file-sidebar {
            width: 200px;
            background-color: #252525;
            border-right: 1px solid #333;
            overflow-y: auto;
        }
        
        .mos-file-sidebar-item {
            padding: 8px 15px;
            cursor: pointer;
            display: flex;
            align-items: center;
        }
        
        .mos-file-sidebar-item:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        .mos-file-sidebar-item.active {
            background-color: rgba(63, 81, 181, 0.2);
        }
        
        .mos-file-sidebar-icon {
            margin-right: 10px;
            font-size: 16px;
        }
        
        .mos-file-main {
            flex: 1;
            overflow: auto;
            padding: 10px;
        }
        
        .mos-file-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
            gap: 10px;
        }
        
        .mos-file-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 10px 5px;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .mos-file-item:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        .mos-file-item.selected {
            background-color: rgba(63, 81, 181, 0.2);
        }
        
        .mos-file-icon {
            font-size: 36px;
            margin-bottom: 5px;
        }
        
        .mos-file-name {
            font-size: 12px;
            text-align: center;
            word-break: break-word;
            max-width: 100%;
        }
        
        /* Terminal */
        .mos-terminal {
            display: flex;
            flex-direction: column;
            height: 100%;
            background-color: #0c0c0c;
            color: #f0f0f0;
            font-family: 'Courier New', monospace;
            padding: 10px;
            overflow: auto;
        }
        
        .mos-terminal-output {
            flex: 1;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.3;
        }
        
        .mos-terminal-input-line {
            display: flex;
            margin-top: 10px;
        }
        
        .mos-terminal-prompt {
            color: #4caf50;
            margin-right: 10px;
        }
        
        .mos-terminal-input {
            flex: 1;
            background: none;
            border: none;
            color: #f0f0f0;
            font-family: 'Courier New', monospace;
            font-size: inherit;
            outline: none;
        }
        
        /* Code Editor */
        .mos-editor {
            display: flex;
            flex-direction: column;
            height: 100%;
        }
        
        .mos-editor-toolbar {
            display: flex;
            align-items: center;
            height: 40px;
            padding: 0 10px;
            background-color: #2a2a2a;
            border-bottom: 1px solid #444;
        }
        
        .mos-editor-main {
            flex: 1;
            display: flex;
        }
        
        .mos-editor-sidebar {
            width: 200px;
            background-color: #252525;
            border-right: 1px solid #333;
            overflow-y: auto;
        }
        
        .mos-editor-content {
            flex: 1;
            position: relative;
        }
        
        .mos-editor-textarea {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            padding: 10px;
            background-color: #1e1e1e;
            color: #f0f0f0;
            border: none;
            resize: none;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            tab-size: 4;
            outline: none;
        }
        
        /* Settings App */
        .mos-settings {
            display: flex;
            height: 100%;
        }
        
        .mos-settings-sidebar {
            width: 220px;
            background-color: #252525;
            border-right: 1px solid #333;
            overflow-y: auto;
            padding: 15px 0;
        }
        
        .mos-settings-nav-item {
            padding: 10px 20px;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .mos-settings-nav-item:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        .mos-settings-nav-item.active {
            background-color: rgba(63, 81, 181, 0.2);
        }
        
        .mos-settings-content {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
        }
        
        .mos-settings-section {
            margin-bottom: 30px;
        }
        
        .mos-settings-section-title {
            font-size: 18px;
            font-weight: 500;
            margin-bottom: 15px;
            color: #3f51b5;
        }
        
        .mos-settings-option {
            margin-bottom: 15px;
        }
        
        .mos-settings-label {
            display: block;
            margin-bottom: 5px;
            font-size: 14px;
        }
        
        .mos-settings-input {
            width: 100%;
            padding: 8px 10px;
            background-color: #333;
            color: #f0f0f0;
            border: 1px solid #444;
            border-radius: 4px;
        }
        
        .mos-settings-select {
            width: 100%;
            padding: 8px 10px;
            background-color: #333;
            color: #f0f0f0;
            border: 1px solid #444;
            border-radius: 4px;
        }
        
        .mos-settings-checkbox {
            margin-right: 8px;
        }
    </style>
    
    <!-- Register Service Worker -->
    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('mos.php?sw=1')
                    .then(registration => {
                        console.log('MOS Service Worker registered with scope:', registration.scope);
                    })
                    .catch(error => {
                        console.error('MOS Service Worker registration failed:', error);
                    });
            });
        }
    </script>
</head>
<body>
    <!-- Splash Screen -->
    <div id="mos-splash-screen" class="mos-splash-screen">
        <img id="splash-logo" src="mos.php?file=/system/logo.svg" alt="MOS Logo">
        <div class="mos-loading-indicator">
            <div class="mos-loading-bar">
                <div id="mos-loading-progress" class="mos-loading-progress"></div>
            </div>
            <div id="mos-loading-status" class="mos-loading-status">Initializing system...</div>
        </div>
    </div>
    
    <!-- Login Screen -->
    <div id="mos-login-screen" class="mos-login-screen">
        <div class="mos-login-container">
            <div class="mos-login-logo">
                <img src="mos.php?file=/system/logo.svg" alt="MOS Logo">
            </div>
            <h2 class="mos-login-heading">Welcome to MOS</h2>
            <form id="mos-login-form" class="mos-login-form">
                <div class="mos-login-input">
                    <input type="text" id="username" name="username" placeholder="Username" required>
                </div>
                <div class="mos-login-input">
                    <input type="password" id="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit" class="mos-login-button">Log In</button>
                <div id="mos-login-error" class="mos-login-error"></div>
            </form>
        </div>
    </div>
    
    <!-- Desktop Environment -->
    <div id="mos-desktop" class="mos-desktop">
        <div id="mos-workspace" class="mos-workspace">
            <!-- Windows will be created here -->
        </div>
        <div id="mos-taskbar" class="mos-taskbar">
            <button id="mos-start-button" class="mos-start-button">MOS</button>
            <div id="mos-taskbar-items" class="mos-taskbar-items">
                <!-- Taskbar items will be created here -->
            </div>
            <div id="mos-system-tray" class="mos-system-tray">
                <div id="mos-clock" class="mos-clock"></div>
            </div>
        </div>
    </div>
    
    <!-- Notification Container -->
    <div id="mos-notification-container" class="mos-notification-container">
        <!-- Notifications will be created here -->
    </div>
    
    <!-- Error Screen -->
    <div id="mos-error-screen" class="mos-error-screen">
        <div class="mos-error-container">
            <h2 id="error-title">System Error</h2>
            <p id="error-message">An error occurred while loading MOS.</p>
            <pre id="error-details" style="display:none"></pre>
            <button id="mos-restart-button">Restart</button>
        </div>
    </div>
    
    <!-- MOS Kernel (main system script) -->
    <script type="module">
        /**
         * MOS Kernel
         * Core system kernel for the MOS operating system
         */
        class MOSKernel {
            /**
             * Create a new kernel instance
             */
            constructor() {
                // System metadata
                this.version = '1.0.0-alpha';
                this.buildDate = new Date('2025-07-04');
                this.codename = 'Genesis';
                
                // System state
                this.state = {
                    status: 'uninitialized', // uninitialized -> initializing -> running -> shuttingDown -> shutdown -> error
                    startTime: null,
                    lastError: null,
                    debug: true
                };
                
                // Core modules
                this.modules = {
                    events: null,     // Event management system
                    security: null,   // Security and permissions
                    filesystem: null, // Virtual file system
                    process: null,    // Process management
                    ui: null          // User interface management
                };
                
                // Runtime data
                this.applications = new Map(); // Running applications
                this.services = new Map();     // Connected services
                this.config = null;            // System configuration
                
                // Current user context
                this.currentUser = null;
                
                // Kernel logger
                this.log = this._createLogger('kernel');
                
                this.log.info(`MOS Kernel v${this.version} (${this.codename}) created`);
            }
            
            /**
             * Initialize the kernel and all core systems
             * @async
             * @returns {Promise<boolean>} True if initialization succeeded
             */
            async initialize() {
                try {
                    this._updateState('initializing');
                    this.state.startTime = Date.now();
                    
                    this.log.info('Kernel initialization started');
                    
                    // Update loading progress
                    this._updateLoadingProgress(10, 'Loading system configuration...');
                    
                    // Step 1: Load core configuration
                    await this._loadConfiguration();
                    
                    // Apply debug setting from config
                    if (this.config && typeof this.config.system.debug === 'boolean') {
                        this.state.debug = this.config.system.debug;
                        this.log.info(`Debug mode: ${this.state.debug ? 'enabled' : 'disabled'}`);
                    }
                    
                    // Update loading progress
                    this._updateLoadingProgress(20, 'Initializing core modules...');
                    
                    // Step 2: Initialize event system
                    this.log.info('Initializing event system...');
                    this.modules.events = new EventSystem(this);
                    
                    // Register for critical system events
                    this._registerSystemEvents();
                    
                    // Update loading progress
                    this._updateLoadingProgress(30, 'Initializing security module...');
                    
                    // Step 3: Initialize security module
                    this.log.info('Initializing security module...');
                    this.modules.security = new SecurityManager(this);
                    
                    // Update loading progress
                    this._updateLoadingProgress(40, 'Initializing filesystem module...');
                    
                    // Step 4: Initialize filesystem module
                    this.log.info('Initializing filesystem module...');
                    this.modules.filesystem = new FileSystem(this);
                    
                    // Update loading progress
                    this._updateLoadingProgress(50, 'Initializing process manager...');
                    
                    // Step 5: Initialize process manager
                    this.log.info('Initializing process manager...');
                    this.modules.process = new ProcessManager(this);
                    
                    // Update loading progress
                    this._updateLoadingProgress(60, 'Connecting to system services...');
                    
                    // Step 6: Connect to essential services
                    this.log.info('Connecting to system services...');
                    await this._connectEssentialServices();
                    
                    // Update loading progress
                    this._updateLoadingProgress(70, 'Initializing user interface...');
                    
                    // Step 7: Initialize UI module
                    this.log.info('Initializing user interface module...');
                    this.modules.ui = new UIManager(this);
                    await this.modules.ui.initialize();
                    
                    // Update loading progress
                    this._updateLoadingProgress(80, 'Loading system state...');
                    
                    // Step 8: Load system state and check authentication
                    this.log.info('Loading system state...');
                    const isAuthenticated = await this._loadSystemState();
                    
                    // Update loading progress
                    this._updateLoadingProgress(90, 'Finalizing system initialization...');
                    
                    // Step 9: Show login screen or desktop based on authentication
                    if (isAuthenticated) {
                        this.log.info('User is authenticated, showing desktop...');
                        this._showDesktop();
                    } else {
                        this.log.info('User is not authenticated, showing login screen...');
                        this._showLoginScreen();
                    }
                    
                    // Kernel is now fully operational
                    this._updateState('running');
                    
                    // Update loading progress to complete
                    this._updateLoadingProgress(100, 'System ready!');
                    
                    const initTime = ((Date.now() - this.state.startTime) / 1000).toFixed(2);
                    this.log.info(`Kernel initialization completed in ${initTime}s`);
                    
                    // Notify system that kernel is ready
                    this.modules.events.emit('system:ready', { 
                        version: this.version,
                        initializationTime: initTime
                    });
                    
                    return true;
                } catch (error) {
                    this.state.lastError = error;
                    this._updateState('error');
                    
                    this.log.error(`Kernel initialization failed: ${error.message}`, error);
                    
                    // Show error screen
                    this._showErrorScreen('System Initialization Failed', error.message, error.stack);
                    
                    return false;
                }
            }
            
            /**
             * Load system configuration
             * @private
             * @async
             */
            async _loadConfiguration() {
                try {
                    // Load main system configuration
                    const response = await fetch('mos.php?api=system&_=' + Date.now(), {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            method: 'getSystemInfo',
                            params: {}
                        })
                    });
                    
                    if (!response.ok) {
                        throw new Error(`Failed to load system configuration: ${response.status} ${response.statusText}`);
                    }
                    
                    const result = await response.json();
                    
                    if (!result.success) {
                        throw new Error(`Failed to load system configuration: ${result.message}`);
                    }
                    
                    this.config = result.data;
                    this.log.info('System configuration loaded successfully');
                    
                    return true;
                } catch (error) {
                    this.log.error('Failed to load system configuration', error);
                    throw new Error(`Configuration loading failed: ${error.message}`);
                }
            }
            
            /**
             * Connect to essential backend services
             * @private
             * @async
             */
            async _connectEssentialServices() {
                try {
                    // Connect to essential services
                    const essentialServices = ['auth', 'users', 'apps', 'filesystem'];
                    
                    for (const serviceName of essentialServices) {
                        this.log.info(`Connecting to ${serviceName} service...`);
                        const service = this._createServiceProxy(serviceName);
                        this.services.set(serviceName, service);
                    }
                    
                    this.log.info('All essential services connected');
                    return true;
                } catch (error) {
                    this.log.error('Failed to connect to essential services', error);
                    throw new Error(`Service connection failed: ${error.message}`);
                }
            }
            
            /**
             * Create a service proxy for API calls
             * @private
             * @param {string} serviceName - Name of the service
             * @returns {Object} Service proxy object
             */
            _createServiceProxy(serviceName) {
                const kernel = this;
                
                return {
                    name: serviceName,
                    status: 'connected',
                    
                    /**
                     * Call a method on the service
                     * @async
                     * @param {string} method - Method name
                     * @param {Object} params - Method parameters
                     * @returns {Promise<any>} Response data
                     */
                    async call(method, params = {}) {
                        try {
                            const requestId = kernel._generateRequestId();
                            
                            // Log the API call in debug mode
                            kernel.log.debug(`API ${this.name}.${method} call`, { requestId, params });
                            
                            // Send request to backend
                            const response = await fetch(`mos.php?api=${this.name}&_=${Date.now()}`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-MOS-Request-ID': requestId
                                },
                                body: JSON.stringify({
                                    method,
                                    params,
                                    _requestId: requestId,
                                    _timestamp: Date.now()
                                }),
                                credentials: 'same-origin' // Include cookies for authentication
                            });
                            
                            // Check for HTTP errors
                            if (!response.ok) {
                                throw new Error(`Service returned status ${response.status} ${response.statusText}`);
                            }
                            
                            // Parse response
                            const result = await response.json();
                            
                            // Check for API errors
                            if (result.success === false) {
                                throw new Error(result.message || 'Unknown service error');
                            }
                            
                            return result.data;
                        } catch (error) {
                            kernel.log.error(`Service ${this.name}.${method} call failed:`, error);
                            throw error;
                        }
                    }
                };
            }
            
            /**
             * Load saved system state and check authentication
             * @private
             * @async
             * @returns {Promise<boolean>} True if user is authenticated
             */
            async _loadSystemState() {
                try {
                    // Check if user is authenticated
                    if (this.services.has('auth')) {
                        this.log.info('Checking authentication state...');
                        
                        const authService = this.services.get('auth');
                        const validationResult = await authService.call('validateToken', {});
                        
                        if (validationResult.valid && validationResult.user) {
                            this.log.info(`Valid session found for user: ${validationResult.user.username}`);
                            
                            // Set current user
                            this.currentUser = validationResult.user;
                            
                            // Update security context with user permissions
                            this.modules.security.handleLogin({
                                user: validationResult.user,
                                permissions: validationResult.permissions || []
                            });
                            
                            // Emit user login event
                            this.modules.events.emit('auth:restored', {
                                user: validationResult.user
                            });
                            
                            return true;
                        } else {
                            this.log.info('No valid authentication session found');
                        }
                    }
                    
                    return false;
                } catch (error) {
                    this.log.error('Failed to load system state', error);
                    // Don't throw here, as we can continue without a restored session
                    return false;
                }
            }
            
            /**
             * Register handlers for critical system events
             * @private
             */
            _registerSystemEvents() {
                // Handle authentication events
                this.modules.events.on('auth:login', (data) => {
                    this.log.info(`User logged in: ${data.user.username}`);
                    this.currentUser = data.user;
                    
                    // Update security context
                    this.modules.security.handleLogin(data);
                    
                    // Show desktop
                    this._showDesktop();
                });
                
                this.modules.events.on('auth:logout', () => {
                    this.log.info('User logged out');
                    this.currentUser = null;
                    
                    // Update security context
                    this.modules.security.handleLogout();
                    
                    // Show login screen
                    this._showLoginScreen();
                });
                
                // Handle system shutdown event
                this.modules.events.on('system:shutdown', (data) => {
                    this.log.info(`System shutdown initiated: ${data.reason}`);
                    this.shutdown(data.reason);
                });
                
                // Handle application lifecycle events
                this.modules.events.on('application:launched', (data) => {
                    this.log.info(`Application launched: ${data.appId} (Process ID: ${data.processId})`);
                });
                
                this.modules.events.on('application:terminated', (data) => {
                    this.log.info(`Application terminated: ${data.appId} (Process ID: ${data.processId})`);
                    
                    // Remove from running applications
                    this.applications.delete(data.processId);
                });
            }
            
            /**
             * Update the loading progress during initialization
             * @private
             * @param {number} progress - Progress percentage (0-100)
             * @param {string} status - Status message
             */
            _updateLoadingProgress(progress, status) {
                const progressBar = document.getElementById('mos-loading-progress');
                const statusText = document.getElementById('mos-loading-status');
                
                if (progressBar) {
                    progressBar.style.width = `${progress}%`;
                }
                
                if (statusText && status) {
                    statusText.textContent = status;
                }
            }
            
            /**
             * Show the login screen
             * @private
             */
            _showLoginScreen() {
                // Hide splash screen
                const splashScreen = document.getElementById('mos-splash-screen');
                splashScreen.classList.add('fade-out');
                
                setTimeout(() => {
                    splashScreen.style.display = 'none';
                    
                    // Show login screen
                    const loginScreen = document.getElementById('mos-login-screen');
                    loginScreen.style.display = 'flex';
                    
                    setTimeout(() => {
                        loginScreen.classList.add('show');
                        
                        // Focus username field
                        document.getElementById('username').focus();
                    }, 50);
                    
                    // Set up login form submission
                    const loginForm = document.getElementById('mos-login-form');
                    const loginError = document.getElementById('mos-login-error');
                    
                    loginForm.onsubmit = async (e) => {
                        e.preventDefault();
                        loginError.textContent = '';
                        
                        const username = document.getElementById('username').value;
                        const password = document.getElementById('password').value;
                        
                        if (!username || !password) {
                            loginError.textContent = 'Please enter both username and password';
                            return;
                        }
                        
                        try {
                            const authService = this.services.get('auth');
                            const result = await authService.call('login', { username, password });
                            
                            // Login successful
                            this.modules.events.emit('auth:login', {
                                user: result.user,
                                permissions: result.permissions
                            });
                            
                            // Reset form
                            loginForm.reset();
                            
                            // Hide login screen
                            loginScreen.classList.remove('show');
                            setTimeout(() => {
                                loginScreen.style.display = 'none';
                            }, 500);
                            
                        } catch (error) {
                            loginError.textContent = error.message || 'Login failed';
                            document.getElementById('password').value = '';
                            document.getElementById('password').focus();
                        }
                    };
                }, 500);
            }
            
            /**
             * Show the desktop environment
             * @private
             */
            _showDesktop() {
                // Hide splash screen
                const splashScreen = document.getElementById('mos-splash-screen');
                splashScreen.classList.add('fade-out');
                
                // Hide login screen if visible
                const loginScreen = document.getElementById('mos-login-screen');
                loginScreen.classList.remove('show');
                
                setTimeout(() => {
                    splashScreen.style.display = 'none';
                    loginScreen.style.display = 'none';
                    
                    // Show desktop
                    const desktop = document.getElementById('mos-desktop');
                    desktop.style.display = 'block';
                    
                    setTimeout(() => {
                        desktop.classList.add('show');
                    }, 50);
                    
                    // Update the clock
                    this._updateClock();
                    setInterval(() => this._updateClock(), 60000);
                    
                    // Set up start button
                    document.getElementById('mos-start-button').addEventListener('click', () => {
                        this.toggleStartMenu();
                    });
                    
                    // Show welcome notification
                    this.modules.ui.showNotification(
                        'Welcome to MOS',
                        `Hello, ${this.currentUser.name}! Welcome to MOS v${this.version}.`,
                        5000
                    );
                }, 500);
            }
            
            /**
             * Show the error screen
             * @private
             * @param {string} title - Error title
             * @param {string} message - Error message
             * @param {string} details - Error details (stack trace)
             */
            _showErrorScreen(title, message, details) {
                // Hide other screens
                document.getElementById('mos-splash-screen').style.display = 'none';
                document.getElementById('mos-login-screen').style.display = 'none';
                document.getElementById('mos-desktop').style.display = 'none';
                
                // Set error information
                document.getElementById('error-title').textContent = title;
                document.getElementById('error-message').textContent = message;
                
                const errorDetails = document.getElementById('error-details');
                if (details) {
                    errorDetails.textContent = details;
                    errorDetails.style.display = 'block';
                }
                
                // Show error screen
                document.getElementById('mos-error-screen').style.display = 'flex';
                
                // Set up restart button
                document.getElementById('mos-restart-button').onclick = () => {
                    window.location.reload();
                };
            }
            
            /**
             * Update the clock element
             * @private
             */
            _updateClock() {
                const clock = document.getElementById('mos-clock');
                if (!clock) return;
                
                const now = new Date();
                const hours = now.getHours().toString().padStart(2, '0');
                const minutes = now.getMinutes().toString().padStart(2, '0');
                clock.textContent = `${hours}:${minutes}`;
            }
            
            /**
             * Toggle the start menu visibility
             */
            toggleStartMenu() {
                // Check if start menu already exists
                let startMenu = document.getElementById('mos-start-menu');
                
                if (startMenu) {
                    // Toggle existing menu
                    if (startMenu.classList.contains('active')) {
                        startMenu.classList.remove('active');
                        setTimeout(() => startMenu.remove(), 300); // Remove after animation
                    } else {
                        startMenu.classList.add('active');
                    }
                    return;
                }
                
                // Create new start menu
                startMenu = document.createElement('div');
                startMenu.id = 'mos-start-menu';
                startMenu.className = 'mos-start-menu';
                
                // Add user info at the top
                const userInfo = document.createElement('div');
                userInfo.className = 'mos-user-info';
                
                const userName = this.currentUser ? this.currentUser.name : 'Guest';
                userInfo.innerHTML = `
                    <div class="mos-user-avatar"></div>
                    <div class="mos-user-name">${userName}</div>
                `;
                
                // Add menu items
                const menuItems = document.createElement('div');
                menuItems.className = 'mos-menu-items';
                
                // Get available applications from the apps service
                this.services.get('apps').call('listApps').then(apps => {
                    let menuHtml = '';
                    
                    // Add apps to menu
                    apps.forEach(app => {
                        menuHtml += `
                            <div class="mos-menu-item" data-app="${app.id}">
                                <span class="mos-menu-item-icon">${app.icon}</span>
                                ${app.title}
                            </div>
                        `;
                    });
                    
                    // Add separator and system options
                    menuHtml += `
                        <div class="mos-menu-separator"></div>
                        <div class="mos-menu-item" data-action="settings">
                            <span class="mos-menu-item-icon">⚙️</span>
                            Settings
                        </div>
                        <div class="mos-menu-item" data-action="logout">
                            <span class="mos-menu-item-icon">🚪</span>
                            Log Out
                        </div>
                    `;
                    
                    menuItems.innerHTML = menuHtml;
                    
                    // Add event listeners for menu items
                    menuItems.querySelectorAll('.mos-menu-item[data-app]').forEach(item => {
                        item.addEventListener('click', () => {
                            const appId = item.getAttribute('data-app');
                            this.launchApplication(appId);
                            this.toggleStartMenu(); // Close menu
                        });
                    });
                    
                    // Add settings action
                    const settingsItem = menuItems.querySelector('.mos-menu-item[data-action="settings"]');
                    if (settingsItem) {
                        settingsItem.addEventListener('click', () => {
                            this.launchApplication('settings');
                            this.toggleStartMenu(); // Close menu
                        });
                    }
                    
                    // Add logout action
                    const logoutItem = menuItems.querySelector('.mos-menu-item[data-action="logout"]');
                    if (logoutItem) {
                        logoutItem.addEventListener('click', () => {
                            this.logout();
                            this.toggleStartMenu(); // Close menu
                        });
                    }
                }).catch(error => {
                    this.log.error('Failed to load app list for start menu', error);
                    menuItems.innerHTML = `
                        <div class="mos-menu-item">Error loading applications</div>
                        <div class="mos-menu-separator"></div>
                        <div class="mos-menu-item" data-action="logout">Log Out</div>
                    `;
                    
                    // Add logout action
                    const logoutItem = menuItems.querySelector('.mos-menu-item[data-action="logout"]');
                    if (logoutItem) {
                        logoutItem.addEventListener('click', () => {
                            this.logout();
                            this.toggleStartMenu(); // Close menu
                        });
                    }
                });
                
                // Assemble menu
                startMenu.appendChild(userInfo);
                startMenu.appendChild(menuItems);
                
                // Add to DOM
                document.body.appendChild(startMenu);
                
                // Trigger animation
                setTimeout(() => startMenu.classList.add('active'), 10);
                
                // Close when clicking outside
                document.addEventListener('click', function closeMenu(e) {
                    if (!startMenu.contains(e.target) && e.target.id !== 'mos-start-button') {
                        startMenu.classList.remove('active');
                        setTimeout(() => {
                            if (startMenu.parentNode) {
                                startMenu.remove();
                            }
                        }, 300);
                        document.removeEventListener('click', closeMenu);
                    }
                });
            }
            
            /**
             * Launch an application
             * @async
             * @param {string} appId - Application identifier
             * @param {Object} params - Launch parameters
             * @returns {Promise<string>} Process ID of the launched application
             */
            async launchApplication(appId, params = {}) {
                try {
                    this.log.info(`Launching application: ${appId}`);
                    
                    // Check if user has permission to run this app
                    if (!this.modules.security.hasPermission(`app.launch.${appId}`)) {
                        this.modules.ui.showNotification(
                            'Permission Denied',
                            `You don't have permission to launch ${appId}`,
                            5000
                        );
                        throw new Error(`Permission denied: Cannot launch ${appId}`);
                    }
                    
                    // Get application metadata from apps service
                    const appInfo = await this.services.get('apps').call('getAppInfo', { appId });
                    
                    if (!appInfo) {
                        throw new Error(`Application not found: ${appId}`);
                    }
                    
                    // Create a new process for the application
                    const process = await this.modules.process.createProcess(appId, appInfo, params);
                    
                    // Add to running applications
                    this.applications.set(process.id, process);
                    
                    // Notify system of new application launch
                    this.modules.events.emit('application:launched', { 
                        appId,
                        processId: process.id,
                        windowId: process.windowId
                    });
                    
                    return process.id;
                } catch (error) {
                    this.log.error(`Failed to launch application ${appId}:`, error);
                    
                    // Notify of launch failure
                    this.modules.events.emit('application:launchFailed', { 
                        appId, 
                        error: error.message
                    });
                    
                    throw error;
                }
            }
            
            /**
             * Log out the current user
             * @async
             */
            async logout() {
                try {
                    this.log.info('Logging out user...');
                    
                    // Call logout API
                    if (this.services.has('auth')) {
                        await this.services.get('auth').call('logout', {});
                    }
                    
                    // Close all running applications
                    for (const [processId, process] of this.applications.entries()) {
                        this.log.info(`Terminating process: ${processId}`);
                        await this.modules.process.terminateProcess(processId);
                    }
                    
                    // Clear current user
                    this.currentUser = null;
                    
                    // Update security context
                    this.modules.security.handleLogout();
                    
                    // Emit logout event
                    this.modules.events.emit('auth:logout', {});
                } catch (error) {
                    this.log.error('Logout failed:', error);
                    throw error;
                }
            }
            
            /**
             * Shut down the system
             * @async
             * @param {string} reason - Reason for shutdown
             */
            async shutdown(reason = 'user_initiated') {
                try {
                    this.log.info(`Initiating system shutdown (Reason: ${reason})...`);
                    this._updateState('shuttingDown');
                    
                    // Emit pre-shutdown event
                    this.modules.events.emit('system:shuttingDown', { reason });
                    
                    // Close all running applications
                    for (const [processId, process] of this.applications.entries()) {
                        this.log.info(`Terminating process: ${processId}`);
                        await this.modules.process.terminateProcess(processId);
                    }
                    
                    // Log out user if logged in
                    if (this.currentUser) {
                        await this.logout();
                    }
                    
                    // Disconnect from all services
                    for (const [serviceName, service] of this.services.entries()) {
                        this.log.info(`Disconnecting from service: ${serviceName}`);
                        service.status = 'disconnected';
                    }
                    
                    // Final shutdown event
                    this.modules.events.emit('system:shutdown', { reason });
                    
                    this._updateState('shutdown');
                    this.log.info('System shutdown complete');
                    
                    // Show shutdown message
                    document.body.innerHTML = `
                        <div style="display:flex;justify-content:center;align-items:center;height:100vh;font-size:24px;background-color:#1e1e1e;color:#f0f0f0;">
                            <div style="text-align:center;">
                                <p>MOS has been shut down.</p>
                                <p style="font-size:16px;margin-top:20px;">Refresh to restart.</p>
                            </div>
                        </div>
                    `;
                    
                    return true;
                } catch (error) {
                    this.log.error('Shutdown failed:', error);
                    this._updateState('error');
                    throw error;
                }
            }
            
            /**
             * Create a logger for a specific component
             * @private
             * @param {string} component - Component name
             * @returns {Object} Logger object
             */
            _createLogger(component) {
                return {
                    /**
                     * Log an informational message
                     * @param {string} message - Message to log
                     * @param {Object} [data] - Additional data to log
                     */
                    info: (message, data) => {
                        if (!this.state.debug && !component.startsWith('kernel')) return;
                        console.info(`[MOS:${component}] ${message}`, data || '');
                    },
                    
                    /**
                     * Log a warning message
                     * @param {string} message - Message to log
                     * @param {Object} [data] - Additional data to log
                     */
                    warn: (message, data) => {
                        console.warn(`[MOS:${component}] ${message}`, data || '');
                    },
                    
                    /**
                     * Log an error message
                     * @param {string} message - Message to log
                     * @param {Error|Object} [error] - Error object or data
                     */
                    error: (message, error) => {
                        console.error(`[MOS:${component}] ${message}`, error || '');
                    },
                    
                    /**
                     * Log a debug message (only shown in debug mode)
                     * @param {string} message - Message to log
                     * @param {Object} [data] - Additional data to log
                     */
                    debug: (message, data) => {
                        if (!this.state.debug) return;
                        console.debug(`[MOS:${component}] ${message}`, data || '');
                    }
                };
            }
            
            /**
             * Update the kernel state
             * @private
             * @param {string} status - New status
             */
            _updateState(status) {
                const previous = this.state.status;
                this.state.status = status;
                this.log.info(`Kernel state updated: ${status}`);

                // Emit state change event if events module is available
                if (this.modules.events) {
                    this.modules.events.emit('kernel:stateChanged', {
                        previousStatus: previous,
                        currentStatus: status
                    });
                }
            }
            
            /**
             * Generate a unique request ID
             * @private
             * @returns {string} Unique ID
             */
            _generateRequestId() {
                return 'req_' + Math.random().toString(36).substring(2, 15) + 
                       Math.random().toString(36).substring(2, 15);
            }
            
            /**
             * Get system information
             * @returns {Object} System information
             */
            getSystemInfo() {
                return {
                    version: this.version,
                    buildDate: this.buildDate,
                    codename: this.codename,
                    status: this.state.status,
                    uptime: this.state.startTime ? Math.floor((Date.now() - this.state.startTime) / 1000) : 0,
                    user: this.currentUser ? {
                        username: this.currentUser.username,
                        name: this.currentUser.name,
                        role: this.currentUser.role
                    } : null,
                    debug: this.state.debug,
                    modules: Object.fromEntries(
                        Object.entries(this.modules)
                            .filter(([_, module]) => module !== null)
                            .map(([name, _]) => [name, true])
                    ),
                    services: Array.from(this.services.keys()),
                    applications: this.applications.size
                };
            }
        }
        
        /**
         * Event System
         * Manages event subscriptions and notifications
         */
        class EventSystem {
            /**
             * Create a new event system
             * @param {MOSKernel} kernel - Kernel reference
             */
            constructor(kernel) {
                this.kernel = kernel;
                this.events = new Map();
                this.log = kernel._createLogger('events');
                
                this.log.info('Event system initialized');
            }
            
            /**
             * Register an event listener
             * @param {string} eventName - Event name to listen for
             * @param {Function} handler - Event handler function
             * @returns {EventSystem} This event system for chaining
             */
            on(eventName, handler) {
                if (!this.events.has(eventName)) {
                    this.events.set(eventName, []);
                }
                
                this.events.get(eventName).push(handler);
                this.log.debug(`Registered handler for event: ${eventName}`);
                
                return this;
            }
            
            /**
             * Remove an event listener
             * @param {string} eventName - Event name
             * @param {Function} [handler] - Event handler (if not provided, all handlers are removed)
             * @returns {EventSystem} This event system for chaining
             */
            off(eventName, handler) {
                if (!this.events.has(eventName)) return this;
                
                if (!handler) {
                    // Remove all handlers
                    this.events.delete(eventName);
                    this.log.debug(`Removed all handlers for event: ${eventName}`);
                } else {
                    // Remove specific handler
                    const handlers = this.events.get(eventName);
                    const index = handlers.indexOf(handler);
                    
                    if (index !== -1) {
                        handlers.splice(index, 1);
                        this.log.debug(`Removed handler for event: ${eventName}`);
                    }
                    
                    if (handlers.length === 0) {
                        this.events.delete(eventName);
                    }
                }
                
                return this;
            }
            
            /**
             * Emit an event
             * @param {string} eventName - Event name to emit
             * @param {Object} data - Event data
             */
            emit(eventName, data = {}) {
                if (!this.events.has(eventName)) {
                    this.log.debug(`No handlers for event: ${eventName}`);
                    return;
                }
                
                this.log.debug(`Emitting event: ${eventName}`, data);
                
                for (const handler of this.events.get(eventName)) {
                    try {
                        handler(data);
                    } catch (error) {
                        this.log.error(`Error in event handler for ${eventName}:`, error);
                    }
                }
            }
        }
        
        /**
         * Security Manager
         * Handles user authentication, permissions, and security policies
         */
        class SecurityManager {
            /**
             * Create a new security manager
             * @param {MOSKernel} kernel - Kernel reference
             */
            constructor(kernel) {
                this.kernel = kernel;
                this.log = kernel._createLogger('security');
                this.permissions = new Set();
                this.user = null;
                
                this.log.info('Security manager initialized');
            }
            
            /**
             * Handle user login
             * @param {Object} data - Login data with user and permissions
             */
            handleLogin(data) {
                this.user = data.user;
                
                // Set permissions
                this.permissions.clear();
                if (Array.isArray(data.permissions)) {
                    data.permissions.forEach(permission => {
                        this.permissions.add(permission);
                    });
                }
                
                this.log.info(`User ${this.user.username} logged in with ${this.permissions.size} permissions`);
            }
            
            /**
             * Handle user logout
             */
            handleLogout() {
                this.user = null;
                this.permissions.clear();
                
                this.log.info('User logged out, permissions cleared');
            }
            
            /**
             * Check if current user has a specific permission
             * @param {string} permission - Permission to check
             * @returns {boolean} True if user has permission
             */
            hasPermission(permission) {
                // No user, no permissions
                if (!this.user) {
                    return false;
                }
                
                // Admin users have all permissions
                if (this.user.role === 'admin') {
                    return true;
                }
                
                // Check for direct permission
                if (this.permissions.has(permission)) {
                    return true;
                }
                
                // Check for wildcard permissions
                const parts = permission.split('.');
                
                for (let i = parts.length; i > 0; i--) {
                    const wildcardPermission = [
                        ...parts.slice(0, i),
                        '*'
                    ].join('.');
                    
                    if (this.permissions.has(wildcardPermission)) {
                        return true;
                    }
                }
                
                return false;
            }
            
            /**
             * Get current user's permissions
             * @returns {Array<string>} List of permissions
             */
            getUserPermissions() {
                return Array.from(this.permissions);
            }
        }
        
        /**
         * File System
         * Provides a virtual file system interface
         */
        class FileSystem {
            /**
             * Create a new file system
             * @param {MOSKernel} kernel - Kernel reference
             */
            constructor(kernel) {
                this.kernel = kernel;
                this.log = kernel._createLogger('filesystem');
                
                this.log.info('File system initialized');
            }
            
            /**
             * Read a file
             * @async
             * @param {string} path - Virtual file path
             * @returns {Promise<Object>} File content and metadata
             */
            async readFile(path) {
                try {
                    this.log.debug(`Reading file: ${path}`);
                    
                    // Check permission
                    if (!this.kernel.modules.security.hasPermission('filesystem.read.*')) {
                        throw new Error('Permission denied');
                    }
                    
                    // Call filesystem service
                    const result = await this.kernel.services.get('filesystem').call('readFile', { path });
                    
                    return result;
                } catch (error) {
                    this.log.error(`Failed to read file ${path}:`, error);
                    throw error;
                }
            }
            
            /**
             * Write a file
             * @async
             * @param {string} path - Virtual file path
             * @param {string} content - File content
             * @returns {Promise<Object>} File metadata
             */
            async writeFile(path, content) {
                try {
                    this.log.debug(`Writing file: ${path}`);
                    
                    // Check permission (more specific permission check could be done based on path)
                    if (!this.kernel.modules.security.hasPermission('filesystem.write.*')) {
                        throw new Error('Permission denied');
                    }
                    
                    // Call filesystem service
                    const result = await this.kernel.services.get('filesystem').call('writeFile', {
                        path,
                        content
                    });
                    
                    return result;
                } catch (error) {
                    this.log.error(`Failed to write file ${path}:`, error);
                    throw error;
                }
            }
            
            /**
             * Delete a file
             * @async
             * @param {string} path - Virtual file path
             * @returns {Promise<boolean>} True if deleted successfully
             */
            async deleteFile(path) {
                try {
                    this.log.debug(`Deleting file: ${path}`);
                    
                    // Check permission
                    if (!this.kernel.modules.security.hasPermission('filesystem.delete.*')) {
                        throw new Error('Permission denied');
                    }
                    
                    // Call filesystem service
                    await this.kernel.services.get('filesystem').call('deleteFile', { path });
                    
                    return true;
                } catch (error) {
                    this.log.error(`Failed to delete file ${path}:`, error);
                    throw error;
                }
            }
            
            /**
             * List directory contents
             * @async
             * @param {string} path - Virtual directory path
             * @returns {Promise<Array>} Directory contents
             */
            async listDirectory(path) {
                try {
                    this.log.debug(`Listing directory: ${path}`);
                    
                    // Check permission
                    if (!this.kernel.modules.security.hasPermission('filesystem.read.*')) {
                        throw new Error('Permission denied');
                    }
                    
                    // Call filesystem service
                    const result = await this.kernel.services.get('filesystem').call('listDirectory', { path });
                    
                    return result;
                } catch (error) {
                    this.log.error(`Failed to list directory ${path}:`, error);
                    throw error;
                }
            }
            
            /**
             * Create a directory
             * @async
             * @param {string} path - Virtual directory path
             * @returns {Promise<boolean>} True if created successfully
             */
            async createDirectory(path) {
                try {
                    this.log.debug(`Creating directory: ${path}`);
                    
                    // Check permission
                    if (!this.kernel.modules.security.hasPermission('filesystem.write.*')) {
                        throw new Error('Permission denied');
                    }
                    
                    // Call filesystem service
                    await this.kernel.services.get('filesystem').call('createDirectory', { path });
                    
                    return true;
                } catch (error) {
                    this.log.error(`Failed to create directory ${path}:`, error);
                    throw error;
                }
            }
        }
        
        /**
         * Process Manager
         * Manages application processes and windows
         */
        class ProcessManager {
            /**
             * Create a new process manager
             * @param {MOSKernel} kernel - Kernel reference
             */
            constructor(kernel) {
                this.kernel = kernel;
                this.log = kernel._createLogger('process');
                this.processes = new Map();
                this.nextPid = 1000;
                this.windowZIndex = 100;
                
                this.log.info('Process manager initialized');
            }
            
            /**
             * Create a new process for an application
             * @async
             * @param {string} appId - Application ID
             * @param {Object} appInfo - Application metadata
             * @param {Object} params - Launch parameters
             * @returns {Promise<Object>} Process object
             */
            async createProcess(appId, appInfo, params = {}) {
                try {
                    const pid = this.nextPid++;
                    
                    this.log.info(`Creating process ${pid} for application ${appId}`);
                    
                    // Create window for the process
                    const windowId = `window-${pid}`;
                    const window = this._createWindow(windowId, appInfo.title || appId, appInfo.icon, appInfo.window);
                    
                    // Create process object
                    const process = {
                        id: pid,
                        appId,
                        windowId,
                        window,
                        startTime: Date.now(),
                        status: 'starting',
                        params
                    };
                    
                    // Store in process map
                    this.processes.set(pid, process);
                    
                    // Initialize the application
                    await this._initializeApplication(process, appInfo);
                    
                    // Update process status
                    process.status = 'running';
                    
                    return process;
                } catch (error) {
                    this.log.error(`Failed to create process for ${appId}:`, error);
                    throw error;
                }
            }
            
            /**
             * Terminate a process
             * @async
             * @param {number} pid - Process ID
             * @returns {Promise<boolean>} True if terminated successfully
             */
            async terminateProcess(pid) {
                try {
                    if (!this.processes.has(pid)) {
                        throw new Error(`Process not found: ${pid}`);
                    }
                    
                    const process = this.processes.get(pid);
                    this.log.info(`Terminating process ${pid} (${process.appId})`);
                    
                    // Update process status
                    process.status = 'terminating';
                    
                    // Remove window
                    this._removeWindow(process.windowId);
                    
                    // Remove taskbar item
                    this._removeTaskbarItem(process.windowId);
                    
                    // Update process status and remove from list
                    process.status = 'terminated';
                    this.processes.delete(pid);
                    
                    // Emit terminated event
                    this.kernel.modules.events.emit('application:terminated', {
                        processId: pid,
                        appId: process.appId
                    });
                    
                    return true;
                } catch (error) {
                    this.log.error(`Failed to terminate process ${pid}:`, error);
                    throw error;
                }
            }
            
            /**
             * Create a window for an application
             * @private
             * @param {string} windowId - Window ID
             * @param {string} title - Window title
             * @param {string} icon - Window icon
             * @param {Object} options - Window options
             * @returns {HTMLElement} Window element
             */
            _createWindow(windowId, title, icon, options = {}) {
                this.log.debug(`Creating window: ${windowId}`);
                
                const workspace = document.getElementById('mos-workspace');
                
                // Create window element
                const window = document.createElement('div');
                window.id = windowId;
                window.className = 'mos-window';
                
                // Set initial position and size
                const width = options.width || 800;
                const height = options.height || 600;
                
                // Center the window
                const workspaceRect = workspace.getBoundingClientRect();
                const left = Math.max(0, (workspaceRect.width - width) / 2);
                const top = Math.max(0, (workspaceRect.height - height) / 2);
                
                window.style.width = `${width}px`;
                window.style.height = `${height}px`;
                window.style.left = `${left}px`;
                window.style.top = `${top}px`;
                window.style.zIndex = this.windowZIndex++;
                
                // Create window content
                window.innerHTML = `
                    <div class="mos-window-header">
                        <div class="mos-window-title">${title}</div>
                        <div class="mos-window-controls">
                            <button class="mos-window-minimize" title="Minimize">_</button>
                            <button class="mos-window-maximize" title="Maximize">□</button>
                            <button class="mos-window-close" title="Close">×</button>
                        </div>
                    </div>
                    <div class="mos-window-content">
                        <div class="mos-app-loading">Loading ${title}...</div>
                    </div>
                `;
                
                // Add window to workspace
                workspace.appendChild(window);
                
                // Add window to taskbar
                this._addTaskbarItem(windowId, title, icon);
                
                // Make window draggable
                this._makeWindowDraggable(window);
                
                // Make window resizable
                if (options.resizable !== false) {
                    this._makeWindowResizable(window);
                }
                
                // Set up window controls
                const minimize = window.querySelector('.mos-window-minimize');
                const maximize = window.querySelector('.mos-window-maximize');
                const close = window.querySelector('.mos-window-close');
                
                minimize.addEventListener('click', () => {
                    window.classList.add('minimized');
                    
                    // Update taskbar item
                    const taskbarItem = document.getElementById(`taskbar-${windowId}`);
                    if (taskbarItem) {
                        taskbarItem.classList.remove('active');
                    }
                });
                
                maximize.addEventListener('click', () => {
                    window.classList.toggle('maximized');
                });
                
                close.addEventListener('click', () => {
                    // Find the process by window ID and terminate it
                    for (const [pid, process] of this.processes.entries()) {
                        if (process.windowId === windowId) {
                            this.terminateProcess(pid);
                            break;
                        }
                    }
                });
                
                // Make window active when clicked
                window.addEventListener('mousedown', () => {
                    this._activateWindow(window);
                });
                
                return window;
            }
            
            /**
             * Remove a window
             * @private
             * @param {string} windowId - Window ID
             */
            _removeWindow(windowId) {
                const window = document.getElementById(windowId);
                if (window) {
                    window.remove();
                }
            }
            
            /**
             * Add a taskbar item for a window
             * @private
             * @param {string} windowId - Window ID
             * @param {string} title - Window title
             * @param {string} icon - Window icon
             */
            _addTaskbarItem(windowId, title, icon) {
                const taskbarItems = document.getElementById('mos-taskbar-items');
                
                const item = document.createElement('div');
                item.id = `taskbar-${windowId}`;
                item.className = 'mos-taskbar-item active';
                item.innerHTML = `
                    <div class="mos-taskbar-item-icon">${icon || '📄'}</div>
                    <div class="mos-taskbar-item-title">${title}</div>
                `;
                
                // Toggle window visibility when taskbar item is clicked
                item.addEventListener('click', () => {
                    const window = document.getElementById(windowId);
                    if (window) {
                        if (window.classList.contains('minimized')) {
                            window.classList.remove('minimized');
                            item.classList.add('active');
                            this._activateWindow(window);
                        } else if (window === this._getActiveWindow()) {
                            window.classList.add('minimized');
                            item.classList.remove('active');
                        } else {
                            this._activateWindow(window);
                        }
                    }
                });
                
                taskbarItems.appendChild(item);
            }
            
            /**
             * Remove a taskbar item
             * @private
             * @param {string} windowId - Window ID
             */
            _removeTaskbarItem(windowId) {
                const taskbarItem = document.getElementById(`taskbar-${windowId}`);
                if (taskbarItem) {
                    taskbarItem.remove();
                }
            }
            
            /**
             * Make a window draggable
             * @private
             * @param {HTMLElement} window - Window element
             */
            _makeWindowDraggable(window) {
                const header = window.querySelector('.mos-window-header');
                
                let isDragging = false;
                let offsetX = 0;
                let offsetY = 0;
                
                header.addEventListener('mousedown', (e) => {
                    // Ignore if clicking on window controls
                    if (e.target.closest('.mos-window-controls')) {
                        return;
                    }
                    
                    // Activate window
                    this._activateWindow(window);
                    
                    // Don't drag if maximized
                    if (window.classList.contains('maximized')) {
                        return;
                    }
                    
                    isDragging = true;
                    
                    const rect = window.getBoundingClientRect();
                    offsetX = e.clientX - rect.left;
                    offsetY = e.clientY - rect.top;
                    
                    // Set initial cursor
                    document.body.style.cursor = 'move';
                    
                    // Prevent text selection while dragging
                    e.preventDefault();
                });
                
                document.addEventListener('mousemove', (e) => {
                    if (!isDragging) return;
                    
                    const workspaceRect = document.getElementById('mos-workspace').getBoundingClientRect();
                    
                    // Calculate new position
                    let left = e.clientX - offsetX;
                    let top = e.clientY - offsetY;
                    
                    // Keep window within workspace bounds
                    left = Math.max(0, Math.min(left, workspaceRect.width - 100));
                    top = Math.max(0, Math.min(top, workspaceRect.height - 30));
                    
                    window.style.left = `${left}px`;
                    window.style.top = `${top}px`;
                });
                
                document.addEventListener('mouseup', () => {
                    if (isDragging) {
                        isDragging = false;
                        document.body.style.cursor = '';
                    }
                });
            }
            
            /**
             * Make a window resizable
             * @private
             * @param {HTMLElement} window - Window element
             */
            _makeWindowResizable(window) {
                // Minimum dimensions
                const minWidth = 300;
                const minHeight = 200;
                
                // Create resize handle
                const resizeHandle = document.createElement('div');
                resizeHandle.className = 'mos-window-resize-handle';
                resizeHandle.style.position = 'absolute';
                resizeHandle.style.right = '0';
                resizeHandle.style.bottom = '0';
                resizeHandle.style.width = '15px';
                resizeHandle.style.height = '15px';
                resizeHandle.style.cursor = 'nwse-resize';
                resizeHandle.style.zIndex = '10';
                
                window.appendChild(resizeHandle);
                
                let isResizing = false;
                let startX = 0;
                let startY = 0;
                let startWidth = 0;
                let startHeight = 0;
                
                resizeHandle.addEventListener('mousedown', (e) => {
                    // Don't resize if maximized
                    if (window.classList.contains('maximized')) {
                        return;
                    }
                    
                    isResizing = true;
                    
                    startX = e.clientX;
                    startY = e.clientY;
                    startWidth = window.offsetWidth;
                    startHeight = window.offsetHeight;
                    
                    // Set cursor
                    document.body.style.cursor = 'nwse-resize';
                    
                    // Prevent text selection while resizing
                    e.preventDefault();
                    
                    // Activate window
                    this._activateWindow(window);
                });
                
                document.addEventListener('mousemove', (e) => {
                    if (!isResizing) return;
                    
                    // Calculate new dimensions
                    const width = Math.max(minWidth, startWidth + (e.clientX - startX));
                    const height = Math.max(minHeight, startHeight + (e.clientY - startY));
                    
                    window.style.width = `${width}px`;
                    window.style.height = `${height}px`;
                });
                
                document.addEventListener('mouseup', () => {
                    if (isResizing) {
                        isResizing = false;
                        document.body.style.cursor = '';
                    }
                });
            }
            
            /**
             * Activate a window (bring to front)
             * @private
             * @param {HTMLElement} window - Window element
             */
            _activateWindow(window) {
                // Update z-index
                window.style.zIndex = this.windowZIndex++;
                
                // Update active status in taskbar
                const windowId = window.id;
                const taskbarItems = document.querySelectorAll('.mos-taskbar-item');
                
                taskbarItems.forEach(item => {
                    item.classList.remove('active');
                });
                
                const activeItem = document.getElementById(`taskbar-${windowId}`);
                if (activeItem) {
                    activeItem.classList.add('active');
                }
            }
            
            /**
             * Get the currently active window
             * @private
             * @returns {HTMLElement|null} Active window element
             */
            _getActiveWindow() {
                const windows = document.querySelectorAll('.mos-window');
                let activeWindow = null;
                let highestZIndex = -1;
                
                windows.forEach(window => {
                    const zIndex = parseInt(window.style.zIndex || 0);
                    if (zIndex > highestZIndex) {
                        highestZIndex = zIndex;
                        activeWindow = window;
                    }
                });
                
                return activeWindow;
            }
            
            /**
             * Initialize an application in a window
             * @private
             * @async
             * @param {Object} process - Process object
             * @param {Object} appInfo - Application metadata
             */
            async _initializeApplication(process, appInfo) {
                try {
                    const windowContent = document.querySelector(`#${process.windowId} .mos-window-content`);
                    
                    // Clear loading indicator
                    windowContent.innerHTML = '';
                    
                    // Create app container
                    const appContainer = document.createElement('div');
                    appContainer.className = `mos-app mos-app-${appInfo.id}`;
                    appContainer.style.height = '100%';
                    windowContent.appendChild(appContainer);
                    
// Load application based on app ID
                    switch (appInfo.id) {
                        case 'files':
                            this._initializeFileManager(appContainer, process, appInfo);
                            break;
                            
                        case 'terminal':
                            this._initializeTerminal(appContainer, process, appInfo);
                            break;
                            
                        case 'editor':
                            this._initializeCodeEditor(appContainer, process, appInfo);
                            break;
                            
                        case 'settings':
                            this._initializeSettings(appContainer, process, appInfo);
                            break;
                            
                        default:
                            appContainer.innerHTML = `
                                <div style="padding: 20px; text-align: center;">
                                    <h3>Application ${appInfo.id} not implemented</h3>
                                    <p>This application is not available in the current version.</p>
                                </div>
                            `;
                    }
                    
                    this.log.info(`Application ${appInfo.id} initialized in window ${process.windowId}`);
                } catch (error) {
                    this.log.error(`Failed to initialize application ${appInfo.id}:`, error);
                    
                    // Show error message in window
                    const windowContent = document.querySelector(`#${process.windowId} .mos-window-content`);
                    windowContent.innerHTML = `
                        <div style="padding: 20px; color: #f44336;">
                            <h3>Application Error</h3>
                            <p>${error.message}</p>
                            <pre style="margin-top: 10px; background: #333; padding: 10px; overflow: auto; font-size: 12px;">${error.stack}</pre>
                        </div>
                    `;
                    
                    throw error;
                }
            }
            
            /**
             * Initialize File Manager application
             * @private
             * @param {HTMLElement} container - Container element
             * @param {Object} process - Process object
             * @param {Object} appInfo - Application metadata
             */
            _initializeFileManager(container, process, appInfo) {
                // Create file manager UI
                container.innerHTML = `
                    <div class="mos-file-manager">
                        <div class="mos-file-toolbar">
                            <button class="mos-button mos-button-secondary" id="${process.windowId}-refresh">Refresh</button>
                            <button class="mos-button mos-button-secondary" id="${process.windowId}-new-folder">New Folder</button>
                            <button class="mos-button mos-button-secondary" id="${process.windowId}-upload">Upload</button>
                        </div>
                        <div class="mos-file-manager-content">
                            <div class="mos-file-sidebar">
                                <div class="mos-file-sidebar-item" data-path="/users/${this.kernel.currentUser.username}">
                                    <div class="mos-file-sidebar-icon">👤</div>
                                    <div>My Files</div>
                                </div>
                                <div class="mos-file-sidebar-item" data-path="/apps">
                                    <div class="mos-file-sidebar-icon">📦</div>
                                    <div>Applications</div>
                                </div>
                                <div class="mos-file-sidebar-item" data-path="/system">
                                    <div class="mos-file-sidebar-icon">⚙️</div>
                                    <div>System</div>
                                </div>
                            </div>
                            <div class="mos-file-main" id="${process.windowId}-file-main">
                                <div class="mos-file-list" id="${process.windowId}-file-list"></div>
                            </div>
                        </div>
                    </div>
                `;
                
                // Current directory state
                const state = {
                    currentPath: `/users/${this.kernel.currentUser.username}`,
                    selectedItems: new Set()
                };
                
                // Load initial directory
                this._loadDirectory(process.windowId, state.currentPath);
                
                // Set up event handlers
                const sidebar = container.querySelector('.mos-file-sidebar');
                
                sidebar.addEventListener('click', (e) => {
                    const item = e.target.closest('.mos-file-sidebar-item');
                    if (item) {
                        const path = item.getAttribute('data-path');
                        state.currentPath = path;
                        this._loadDirectory(process.windowId, path);
                        
                        // Update active sidebar item
                        sidebar.querySelectorAll('.mos-file-sidebar-item').forEach(el => {
                            el.classList.remove('active');
                        });
                        item.classList.add('active');
                    }
                });
                
                // Set up toolbar buttons
                document.getElementById(`${process.windowId}-refresh`).addEventListener('click', () => {
                    this._loadDirectory(process.windowId, state.currentPath);
                });
                
                document.getElementById(`${process.windowId}-new-folder`).addEventListener('click', () => {
                    const folderName = prompt('Enter folder name:');
                    if (folderName) {
                        this._createFolder(process.windowId, state.currentPath, folderName);
                    }
                });
                
                // Select initial sidebar item
                sidebar.querySelector(`[data-path="${state.currentPath}"]`).classList.add('active');
            }
            
            /**
             * Load directory contents in file manager
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - Directory path
             */
            async _loadDirectory(windowId, path) {
                try {
                    const fileList = document.getElementById(`${windowId}-file-list`);
                    fileList.innerHTML = '<div class="mos-file-loading">Loading...</div>';
                    
                    // Get directory contents
                    const items = await this.kernel.modules.filesystem.listDirectory(path);
                    
                    // Build file list HTML
                    let html = '';
                    
                    if (path !== '/') {
                        // Add parent directory link
                        const parentPath = path.substring(0, path.lastIndexOf('/'));
                        const parentDir = parentPath || '/';
                        
                        html += `
                            <div class="mos-file-item" data-path="${parentDir}" data-type="directory">
                                <div class="mos-file-icon">📂</div>
                                <div class="mos-file-name">..</div>
                            </div>
                        `;
                    }
                    
                    // Add items
                    items.forEach(item => {
                        const icon = item.type === 'directory' ? '📁' : this._getFileIcon(item.extension);
                        
                        html += `
                            <div class="mos-file-item" data-path="${item.path}" data-type="${item.type}">
                                <div class="mos-file-icon">${icon}</div>
                                <div class="mos-file-name">${item.name}</div>
                            </div>
                        `;
                    });
                    
                    fileList.innerHTML = html;
                    
                    // Add click handler for items
                    fileList.querySelectorAll('.mos-file-item').forEach(item => {
                        item.addEventListener('click', (e) => {
                            const path = item.getAttribute('data-path');
                            const type = item.getAttribute('data-type');
                            
                            if (type === 'directory') {
                                this._loadDirectory(windowId, path);
                            } else {
                                this._openFile(windowId, path);
                            }
                        });
                    });
                    
                } catch (error) {
                    const fileList = document.getElementById(`${windowId}-file-list`);
                    fileList.innerHTML = `
                        <div style="padding: 20px; color: #f44336;">
                            <h3>Error Loading Directory</h3>
                            <p>${error.message}</p>
                        </div>
                    `;
                }
            }
            
            /**
             * Create a new folder
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - Parent directory path
             * @param {string} folderName - New folder name
             */
            async _createFolder(windowId, path, folderName) {
                try {
                    const newPath = `${path}/${folderName}`.replace(/\/+/g, '/');
                    
                    await this.kernel.modules.filesystem.createDirectory(newPath);
                    
                    // Refresh directory
                    this._loadDirectory(windowId, path);
                    
                    // Show notification
                    this.kernel.modules.ui.showNotification(
                        'Folder Created',
                        `Created folder: ${folderName}`,
                        3000
                    );
                } catch (error) {
                    this.kernel.modules.ui.showNotification(
                        'Error',
                        `Failed to create folder: ${error.message}`,
                        5000
                    );
                }
            }
            
            /**
             * Open a file
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - File path
             */
            async _openFile(windowId, path) {
                try {
                    // Get file extension
                    const extension = path.split('.').pop().toLowerCase();
                    
                    // Determine which app to use based on extension
                    let appId = 'editor'; // Default to editor
                    
                    if (['jpg', 'jpeg', 'png', 'gif', 'svg'].includes(extension)) {
                        appId = 'image-viewer';
                    } else if (['mp3', 'wav', 'ogg'].includes(extension)) {
                        appId = 'audio-player';
                    } else if (['mp4', 'webm'].includes(extension)) {
                        appId = 'video-player';
                    } else if (['pdf'].includes(extension)) {
                        appId = 'pdf-viewer';
                    }
                    
                    // Launch appropriate app with file path
                    this.kernel.launchApplication(appId, { filePath: path });
                    
                } catch (error) {
                    this.kernel.modules.ui.showNotification(
                        'Error',
                        `Failed to open file: ${error.message}`,
                        5000
                    );
                }
            }
            
            /**
             * Get icon for file type
             * @private
             * @param {string} extension - File extension
             * @returns {string} Icon emoji
             */
            _getFileIcon(extension) {
                if (!extension) return '📄';
                
                const icons = {
                    // Text files
                    'txt': '📝',
                    'md': '📝',
                    'html': '🌐',
                    'css': '🎨',
                    'js': '📜',
                    'json': '📋',
                    'xml': '📋',
                    'php': '🐘',
                    'py': '🐍',
                    'java': '☕',
                    'c': '©️',
                    'cpp': '©️',
                    'h': '©️',
                    'cs': '©️',
                    'rb': '💎',
                    'go': '🔹',
                    'rs': '🦀',
                    
                    // Images
                    'jpg': '🖼️',
                    'jpeg': '🖼️',
                    'png': '🖼️',
                    'gif': '🖼️',
                    'svg': '🖼️',
                    'ico': '🖼️',
                    
                    // Documents
                    'pdf': '📕',
                    'doc': '📘',
                    'docx': '📘',
                    'xls': '📗',
                    'xlsx': '📗',
                    'ppt': '📙',
                    'pptx': '📙',
                    
                    // Archives
                    'zip': '🗜️',
                    'rar': '🗜️',
                    'tar': '🗜️',
                    'gz': '🗜️',
                    '7z': '🗜️',
                    
                    // Media
                    'mp3': '🎵',
                    'wav': '🎵',
                    'ogg': '🎵',
                    'mp4': '🎬',
                    'avi': '🎬',
                    'mov': '🎬',
                    'webm': '🎬',
                    
                    // Executables
                    'exe': '⚙️',
                    'dll': '⚙️',
                    'bat': '⚙️',
                    'sh': '⚙️',
                    
                    // Misc
                    'log': '📋',
                    'bak': '🔄'
                };
                
                return icons[extension.toLowerCase()] || '📄';
            }
            
            /**
             * Initialize Terminal application
             * @private
             * @param {HTMLElement} container - Container element
             * @param {Object} process - Process object
             * @param {Object} appInfo - Application metadata
             */
            _initializeTerminal(container, process, appInfo) {
                // Create terminal UI
                container.innerHTML = `
                    <div class="mos-terminal">
                        <div class="mos-terminal-output" id="${process.windowId}-terminal-output"></div>
                        <div class="mos-terminal-input-line">
                            <div class="mos-terminal-prompt" id="${process.windowId}-terminal-prompt">user@mos:~$</div>
                            <input type="text" class="mos-terminal-input" id="${process.windowId}-terminal-input" autocomplete="off">
                        </div>
                    </div>
                `;
                
                // Terminal state
                const state = {
                    history: [],
                    historyIndex: -1,
                    currentDirectory: `/users/${this.kernel.currentUser.username}`
                };
                
                // Show welcome message
                const output = document.getElementById(`${process.windowId}-terminal-output`);
                output.innerHTML = `
                    <div style="color: #4caf50; margin-bottom: 10px;">
                        MOS Terminal v1.0.0
                    </div>
                    <div style="color: #ccc; margin-bottom: 10px;">
                        Type 'help' for a list of available commands.
                    </div>
                `;
                
                // Update prompt with current directory
                this._updateTerminalPrompt(process.windowId, state);
                
                // Set up input handler
                const input = document.getElementById(`${process.windowId}-terminal-input`);
                input.focus();
                
                input.addEventListener('keydown', async (e) => {
                    if (e.key === 'Enter') {
                        const command = input.value.trim();
                        
                        if (command) {
                            // Add to history
                            state.history.push(command);
                            state.historyIndex = state.history.length;
                            
                            // Clear input
                            input.value = '';
                            
                            // Show command in output
                            const prompt = document.getElementById(`${process.windowId}-terminal-prompt`);
                            this._appendTerminalOutput(process.windowId, `<span style="color: #4caf50;">${prompt.textContent}</span> ${command}`);
                            
                            // Process command
                            await this._processTerminalCommand(process.windowId, command, state);
                        }
                    } else if (e.key === 'ArrowUp') {
                        // Navigate history up
                        if (state.historyIndex > 0) {
                            state.historyIndex--;
                            input.value = state.history[state.historyIndex];
                            
                            // Move cursor to end
                            setTimeout(() => {
                                input.selectionStart = input.selectionEnd = input.value.length;
                            }, 0);
                        }
                        e.preventDefault();
                    } else if (e.key === 'ArrowDown') {
                        // Navigate history down
                        if (state.historyIndex < state.history.length - 1) {
                            state.historyIndex++;
                            input.value = state.history[state.historyIndex];
                        } else {
                            state.historyIndex = state.history.length;
                            input.value = '';
                        }
                        e.preventDefault();
                    }
                });
                
                // Focus input when terminal is clicked
                container.addEventListener('click', () => {
                    input.focus();
                });
            }
            
            /**
             * Update terminal prompt
             * @private
             * @param {string} windowId - Window ID
             * @param {Object} state - Terminal state
             */
            _updateTerminalPrompt(windowId, state) {
                const prompt = document.getElementById(`${windowId}-terminal-prompt`);
                const directory = state.currentDirectory.replace(`/users/${this.kernel.currentUser.username}`, '~');
                prompt.textContent = `${this.kernel.currentUser.username}@mos:${directory}$`;
            }
            
            /**
             * Append output to terminal
             * @private
             * @param {string} windowId - Window ID
             * @param {string} text - Output text
             */
            _appendTerminalOutput(windowId, text) {
                const output = document.getElementById(`${windowId}-terminal-output`);
                output.innerHTML += `<div>${text}</div>`;
                output.scrollTop = output.scrollHeight;
            }
            
            /**
             * Process terminal command
             * @private
             * @param {string} windowId - Window ID
             * @param {string} command - Command text
             * @param {Object} state - Terminal state
             */
            async _processTerminalCommand(windowId, command, state) {
                try {
                    // Parse command and arguments
                    const parts = command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
                    const cmd = parts[0].toLowerCase();
                    const args = parts.slice(1).map(arg => arg.replace(/^["']|["']$/g, ''));
                    
                    // Process command
                    switch (cmd) {
                        case 'help':
                            this._appendTerminalOutput(windowId, `
                                <div style="color: #4caf50; margin-bottom: 5px;">Available commands:</div>
                                <div style="margin-left: 10px;">help - Show this help message</div>
                                <div style="margin-left: 10px;">clear - Clear terminal output</div>
                                <div style="margin-left: 10px;">echo [text] - Print text</div>
                                <div style="margin-left: 10px;">ls [path] - List directory contents</div>
                                <div style="margin-left: 10px;">cd [path] - Change directory</div>
                                <div style="margin-left: 10px;">mkdir [path] - Create directory</div>
                                <div style="margin-left: 10px;">touch [path] - Create empty file</div>
                                <div style="margin-left: 10px;">cat [path] - Display file contents</div>
                                <div style="margin-left: 10px;">rm [path] - Remove file or directory</div>
                                <div style="margin-left: 10px;">pwd - Print working directory</div>
                                <div style="margin-left: 10px;">whoami - Print current user</div>
                                <div style="margin-left: 10px;">date - Print current date and time</div>
                                <div style="margin-left: 10px;">sandbox [code] - Execute sandboxed PHP code</div>
                                <div style="margin-left: 10px;">exit - Close terminal</div>
                            `);
                            break;
                            
                        case 'clear':
                            document.getElementById(`${windowId}-terminal-output`).innerHTML = '';
                            break;
                            
                        case 'echo':
                            this._appendTerminalOutput(windowId, args.join(' '));
                            break;
                            
                        case 'ls':
                            await this._terminalListDirectory(windowId, args[0] || state.currentDirectory);
                            break;
                            
                        case 'cd':
                            await this._terminalChangeDirectory(windowId, args[0] || `/users/${this.kernel.currentUser.username}`, state);
                            break;
                            
                        case 'mkdir':
                            if (!args[0]) {
                                this._appendTerminalOutput(windowId, '<span style="color: #f44336;">Error: Missing directory name</span>');
                                break;
                            }
                            await this._terminalCreateDirectory(windowId, args[0], state);
                            break;
                            
                        case 'touch':
                            if (!args[0]) {
                                this._appendTerminalOutput(windowId, '<span style="color: #f44336;">Error: Missing file name</span>');
                                break;
                            }
                            await this._terminalCreateFile(windowId, args[0], state);
                            break;
                            
                        case 'cat':
                            if (!args[0]) {
                                this._appendTerminalOutput(windowId, '<span style="color: #f44336;">Error: Missing file name</span>');
                                break;
                            }
                            await this._terminalCatFile(windowId, args[0], state);
                            break;
                            
                        case 'rm':
                            if (!args[0]) {
                                this._appendTerminalOutput(windowId, '<span style="color: #f44336;">Error: Missing path</span>');
                                break;
                            }
                            await this._terminalRemoveFile(windowId, args[0], state);
                            break;
                            
                        case 'pwd':
                            this._appendTerminalOutput(windowId, state.currentDirectory);
                            break;
                            
                        case 'whoami':
                            this._appendTerminalOutput(windowId, this.kernel.currentUser.username);
                            break;
                            
                        case 'date':
                            this._appendTerminalOutput(windowId, new Date().toString());
                            break;
                            
                        case 'sandbox':
                            if (args.length === 0) {
                                this._appendTerminalOutput(windowId, '<span style="color: #f44336;">Error: Missing code to execute</span>');
                                break;
                            }
                            await this._terminalSandbox(windowId, args.join(' '));
                            break;
                            
                        case 'exit':
                            // Find the process by window ID and terminate it
                            for (const [pid, process] of this.processes.entries()) {
                                if (process.windowId === windowId) {
                                    this.terminateProcess(pid);
                                    break;
                                }
                            }
                            break;
                            
                        default:
                            this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Command not found: ${cmd}</span>`);
                    }
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
                
                // Focus input
                document.getElementById(`${windowId}-terminal-input`).focus();
            }
            
            /**
             * Terminal command: List directory
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - Directory path
             */
            async _terminalListDirectory(windowId, path) {
                try {
                    // Resolve path if relative
                    const fullPath = this._resolvePath(path, state.currentDirectory);
                    
                    // Get directory contents
                    const items = await this.kernel.modules.filesystem.listDirectory(fullPath);
                    
                    // Format output
                    let output = '';
                    
                    // Group by type
                    const dirs = items.filter(item => item.type === 'directory');
                    const files = items.filter(item => item.type === 'file');
                    
                    // Sort alphabetically
                    dirs.sort((a, b) => a.name.localeCompare(b.name));
                    files.sort((a, b) => a.name.localeCompare(b.name));
                    
                    // Add directories
                    dirs.forEach(item => {
                        const date = new Date(item.modified * 1000).toISOString().slice(0, 10);
                        output += `<span style="color: #4caf50;">drwxr-xr-x</span> ${date} <span style="color: #3f51b5;">${item.name}/</span>\n`;
                    });
                    
                    // Add files
                    files.forEach(item => {
                        const date = new Date(item.modified * 1000).toISOString().slice(0, 10);
                        const size = this._formatFileSize(item.size);
                        output += `<span style="color: #ccc;">-rw-r--r--</span> ${date} ${size.padStart(8)} ${item.name}\n`;
                    });
                    
                    // Show output
                    this._appendTerminalOutput(windowId, `<pre style="margin: 0;">${output}</pre>`);
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
            }
            
            /**
             * Terminal command: Change directory
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - Directory path
             * @param {Object} state - Terminal state
             */
            async _terminalChangeDirectory(windowId, path, state) {
                try {
                    // Resolve path if relative
                    const fullPath = this._resolvePath(path, state.currentDirectory);
                    
                    // Verify directory exists
                    await this.kernel.modules.filesystem.listDirectory(fullPath);
                    
                    // Update current directory
                    state.currentDirectory = fullPath;
                    
                    // Update prompt
                    this._updateTerminalPrompt(windowId, state);
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
            }
            
            /**
             * Terminal command: Create directory
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - Directory path
             * @param {Object} state - Terminal state
             */
            async _terminalCreateDirectory(windowId, path, state) {
                try {
                    // Resolve path if relative
                    const fullPath = this._resolvePath(path, state.currentDirectory);
                    
                    // Create directory
                    await this.kernel.modules.filesystem.createDirectory(fullPath);
                    
                    this._appendTerminalOutput(windowId, `Directory created: ${fullPath}`);
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
            }
            
            /**
             * Terminal command: Create file
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - File path
             * @param {Object} state - Terminal state
             */
            async _terminalCreateFile(windowId, path, state) {
                try {
                    // Resolve path if relative
                    const fullPath = this._resolvePath(path, state.currentDirectory);
                    
                    // Create empty file
                    await this.kernel.modules.filesystem.writeFile(fullPath, '');
                    
                    this._appendTerminalOutput(windowId, `File created: ${fullPath}`);
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
            }
            
            /**
             * Terminal command: Display file contents
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - File path
             * @param {Object} state - Terminal state
             */
            async _terminalCatFile(windowId, path, state) {
                try {
                    // Resolve path if relative
                    const fullPath = this._resolvePath(path, state.currentDirectory);
                    
                    // Read file
                    const file = await this.kernel.modules.filesystem.readFile(fullPath);
                    
                    // Display content
                    this._appendTerminalOutput(windowId, `<pre style="margin: 0;">${file.content}</pre>`);
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
            }
            
            /**
             * Terminal command: Remove file
             * @private
             * @param {string} windowId - Window ID
             * @param {string} path - File path
             * @param {Object} state - Terminal state
             */
            async _terminalRemoveFile(windowId, path, state) {
                try {
                    // Resolve path if relative
                    const fullPath = this._resolvePath(path, state.currentDirectory);
                    
                    // Delete file
                    await this.kernel.modules.filesystem.deleteFile(fullPath);
                    
                    this._appendTerminalOutput(windowId, `Deleted: ${fullPath}`);
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
            }
            
            /**
             * Terminal command: Execute code in sandbox
             * @private
             * @param {string} windowId - Window ID
             * @param {string} code - PHP code
             */
            async _terminalSandbox(windowId, code) {
                try {
                    if (!this.kernel.modules.security.hasPermission('sandbox.execute.*')) {
                        throw new Error('Permission denied: You do not have sandbox execution permissions');
                    }
                    
                    this._appendTerminalOutput(windowId, '<span style="color: #3f51b5;">Executing code in sandbox...</span>');
                    
                    // Execute in sandbox
                    const result = await this.kernel.services.get('sandbox').call('execute', {
                        code,
                        context: 'terminal'
                    });
                    
                    // Display output
                    let output = result.output || '';
                    
                    if (result.errors) {
                        output += `\n<span style="color: #f44336;">${result.errors}</span>`;
                    }
                    
                    this._appendTerminalOutput(windowId, `<pre style="margin: 0;">${output}</pre>`);
                } catch (error) {
                    this._appendTerminalOutput(windowId, `<span style="color: #f44336;">Error: ${error.message}</span>`);
                }
            }
            
            /**
             * Resolve a relative path
             * @private
             * @param {string} path - Path to resolve
             * @param {string} currentDir - Current directory
             * @returns {string} Resolved path
             */
            _resolvePath(path, currentDir) {
                // Absolute path
                if (path.startsWith('/')) {
                    return path;
                }
                
                // Home directory
                if (path.startsWith('~')) {
                    return path.replace('~', `/users/${this.kernel.currentUser.username}`);
                }
                
                // Relative path
                let resolvedPath = currentDir;
                
                // Handle current directory and parent directory references
                const parts = path.split('/');
                
                for (const part of parts) {
                    if (part === '' || part === '.') {
                        continue;
                    } else if (part === '..') {
                        // Go to parent directory
                        resolvedPath = resolvedPath.replace(/\/[^/]+$/, '') || '/';
                    } else {
                        // Add path component
                        resolvedPath = `${resolvedPath}/${part}`;
                    }
                }
                
                return resolvedPath;
            }
            
            /**
             * Format file size
             * @private
             * @param {number} bytes - Size in bytes
             * @returns {string} Formatted size
             */
            _formatFileSize(bytes) {
                if (bytes < 1024) {
                    return `${bytes}B`;
                } else if (bytes < 1024 * 1024) {
                    return `${(bytes / 1024).toFixed(1)}K`;
                } else if (bytes < 1024 * 1024 * 1024) {
                    return `${(bytes / (1024 * 1024)).toFixed(1)}M`;
                } else {
                    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}G`;
                }
            }
            
            /**
             * Initialize Code Editor application
             * @private
             * @param {HTMLElement} container - Container element
             * @param {Object} process - Process object
             * @param {Object} appInfo - Application metadata
             */
            _initializeCodeEditor(container, process, appInfo) {
                // Create editor UI
                container.innerHTML = `
                    <div class="mos-editor">
                        <div class="mos-editor-toolbar">
                            <button class="mos-button mos-button-secondary" id="${process.windowId}-new">New</button>
                            <button class="mos-button mos-button-secondary" id="${process.windowId}-open">Open</button>
                            <button class="mos-button mos-button-primary" id="${process.windowId}-save">Save</button>
                            <span id="${process.windowId}-filename" style="margin-left: 20px; color: #ccc;">Untitled</span>
                        </div>
                        <div class="mos-editor-main">
                            <div class="mos-editor-content">
                                <textarea class="mos-editor-textarea" id="${process.windowId}-editor" spellcheck="false"></textarea>
                            </div>
                        </div>
                    </div>
                `;
                
                // Editor state
                const state = {
                    currentFile: null,
                    modified: false
                };
                
                // Set up event handlers
                const editor = document.getElementById(`${process.windowId}-editor`);
                const filenameDisplay = document.getElementById(`${process.windowId}-filename`);
                
                // New button
                document.getElementById(`${process.windowId}-new`).addEventListener('click', () => {
                    if (state.modified) {
                        if (!confirm('You have unsaved changes. Create new file anyway?')) {
                            return;
                        }
                    }
                    
                    editor.value = '';
                    state.currentFile = null;
                    state.modified = false;
                    filenameDisplay.textContent = 'Untitled';
                });
                
                // Open button
                document.getElementById(`${process.windowId}-open`).addEventListener('click', async () => {
                    if (state.modified) {
                        if (!confirm('You have unsaved changes. Open another file anyway?')) {
                            return;
                        }
                    }
                    
                    try {
                        // Show file selection dialog (simplified for demo)
                        const path = prompt('Enter file path to open:', `/users/${this.kernel.currentUser.username}/`);
                        
                        if (!path) return;
                        
                        // Load file
                        const file = await this.kernel.modules.filesystem.readFile(path);
                        
                        // Update editor
                        editor.value = file.content;
                        state.currentFile = path;
                        state.modified = false;
                        filenameDisplay.textContent = path.split('/').pop();
                        
                        // Show notification
                        this.kernel.modules.ui.showNotification(
                            'File Opened',
                            `Opened: ${path}`,
                            3000
                        );
                    } catch (error) {
                        this.kernel.modules.ui.showNotification(
                            'Error',
                            `Failed to open file: ${error.message}`,
                            5000
                        );
                    }
                });
                
                // Save button
                document.getElementById(`${process.windowId}-save`).addEventListener('click', async () => {
                    try {
                        let path = state.currentFile;
                        
                        if (!path) {
                            // Ask for file path
                            path = prompt('Enter file path to save:', `/users/${this.kernel.currentUser.username}/untitled.txt`);
                            
                            if (!path) return;
                        }
                        
                        // Save file
                        await this.kernel.modules.filesystem.writeFile(path, editor.value);
                        
                        // Update state
                        state.currentFile = path;
                        state.modified = false;
                        filenameDisplay.textContent = path.split('/').pop();
                        
                        // Show notification
                        this.kernel.modules.ui.showNotification(
                            'File Saved',
                            `Saved: ${path}`,
                            3000
                        );
                    } catch (error) {
                        this.kernel.modules.ui.showNotification(
                            'Error',
                            `Failed to save file: ${error.message}`,
                            5000
                        );
                    }
                });
                
                // Track modifications
                editor.addEventListener('input', () => {
                    if (!state.modified) {
                        state.modified = true;
                        filenameDisplay.textContent = `${filenameDisplay.textContent} *`;
                    }
                });
                
                // Check for file parameter
                if (process.params.filePath) {
                    // Load the file
                    this.kernel.modules.filesystem.readFile(process.params.filePath)
                        .then(file => {
                            editor.value = file.content;
                            state.currentFile = process.params.filePath;
                            state.modified = false;
                            filenameDisplay.textContent = process.params.filePath.split('/').pop();
                        })
                        .catch(error => {
                            this.kernel.modules.ui.showNotification(
                                'Error',
                                `Failed to open file: ${error.message}`,
                                5000
                            );
                        });
                }
            }
            
            /**
             * Initialize Settings application
             * @private
             * @param {HTMLElement} container - Container element
             * @param {Object} process - Process object
             * @param {Object} appInfo - Application metadata
             */
            _initializeSettings(container, process, appInfo) {
                // Create settings UI
                container.innerHTML = `
                    <div class="mos-settings">
                        <div class="mos-settings-sidebar">
                            <div class="mos-settings-nav-item active" data-section="appearance">Appearance</div>
                            <div class="mos-settings-nav-item" data-section="system">System</div>
                            <div class="mos-settings-nav-item" data-section="security">Security</div>
                            <div class="mos-settings-nav-item" data-section="network">Network</div>
                            <div class="mos-settings-nav-item" data-section="about">About</div>
                        </div>
                        <div class="mos-settings-content" id="${process.windowId}-settings-content">
                            <!-- Content will be loaded here -->
                        </div>
                    </div>
                `;
                
                // Load initial section
                this._loadSettingsSection(process.windowId, 'appearance');
                
                // Set up navigation
                const sidebar = container.querySelector('.mos-settings-sidebar');
                
                sidebar.addEventListener('click', (e) => {
                    const item = e.target.closest('.mos-settings-nav-item');
                    if (item) {
                        const section = item.getAttribute('data-section');
                        
                        // Update active item
                        sidebar.querySelectorAll('.mos-settings-nav-item').forEach(el => {
                            el.classList.remove('active');
                        });
                        item.classList.add('active');
                        
                        // Load section
                        this._loadSettingsSection(process.windowId, section);
                    }
                });
            }
            
            /**
             * Load settings section
             * @private
             * @param {string} windowId - Window ID
             * @param {string} section - Section name
             */
            async _loadSettingsSection(windowId, section) {
                const content = document.getElementById(`${windowId}-settings-content`);
                
                switch (section) {
                    case 'appearance':
                        content.innerHTML = `
                            <div class="mos-settings-section">
                                <h2 class="mos-settings-section-title">Appearance Settings</h2>
                                
                                <div class="mos-settings-option">
                                    <label class="mos-settings-label">Theme</label>
                                    <select class="mos-settings-select" id="${windowId}-setting-theme">
                                        <option value="dark">Dark</option>
                                        <option value="light">Light</option>
                                        <option value="blue">Blue</option>
                                    </select>
                                </div>
                                
                                <div class="mos-settings-option">
                                    <label class="mos-settings-label">Font Size</label>
                                    <select class="mos-settings-select" id="${windowId}-setting-font-size">
                                        <option value="small">Small</option>
                                        <option value="medium">Medium</option>
                                        <option value="large">Large</option>
                                    </select>
                                </div>
                                
                                <div class="mos-settings-option">
                                    <label class="mos-settings-label">
                                        <input type="checkbox" class="mos-settings-checkbox" id="${windowId}-setting-animations">
                                        Enable animations
                                    </label>
                                </div>
                                
                                <div class="mos-settings-option">
                                    <button class="mos-button mos-button-primary" id="${windowId}-save-appearance">
                                        Save Changes
                                    </button>
                                </div>
                            </div>
                        `;
                        
                        // Set initial values
                        document.getElementById(`${windowId}-setting-theme`).value = 
                            this.kernel.config.ui.theme || 'dark';
                        document.getElementById(`${windowId}-setting-font-size`).value = 
                            this.kernel.config.ui.fontSize || 'medium';
                        document.getElementById(`${windowId}-setting-animations`).checked = 
                            this.kernel.config.ui.animations !== false;
                        
                        // Save button
                        document.getElementById(`${windowId}-save-appearance`).addEventListener('click', async () => {
                            try {
                                // Get values
                                const theme = document.getElementById(`${windowId}-setting-theme`).value;
                                const fontSize = document.getElementById(`${windowId}-setting-font-size`).value;
                                const animations = document.getElementById(`${windowId}-setting-animations`).checked;
                                
                                // Save to config
                                await this.kernel.services.get('system').call('updateConfig', {
                                    key: 'ui.theme',
                                    value: theme
                                });
                                
                                await this.kernel.services.get('system').call('updateConfig', {
                                    key: 'ui.fontSize',
                                    value: fontSize
                                });
                                
                                await this.kernel.services.get('system').call('updateConfig', {
                                    key: 'ui.animations',
                                    value: animations
                                });
                                
                                // Apply changes
                                this.kernel.config.ui.theme = theme;
                                this.kernel.config.ui.fontSize = fontSize;
                                this.kernel.config.ui.animations = animations;
                                
                                // Update UI
                                this.kernel.modules.ui.applyTheme(theme);
                                
                                // Show notification
                                this.kernel.modules.ui.showNotification(
                                    'Settings Saved',
                                    'Appearance settings have been updated',
                                    3000
                                );
                            } catch (error) {
                                this.kernel.modules.ui.showNotification(
                                    'Error',
                                    `Failed to save settings: ${error.message}`,
                                    5000
                                );
                            }
                        });
                        break;
                        
                    case 'system':
                        content.innerHTML = `
                            <div class="mos-settings-section">
                                <h2 class="mos-settings-section-title">System Settings</h2>
                                
                                <div class="mos-settings-option">
                                    <label class="mos-settings-label">
                                        <input type="checkbox" class="mos-settings-checkbox" id="${windowId}-setting-debug">
                                        Debug Mode
                                    </label>
                                </div>
                                
                                <div class="mos-settings-option">
                                    <label class="mos-settings-label">
                                        <input type="checkbox" class="mos-settings-checkbox" id="${windowId}-setting-auto-login">
                                        Auto-login on startup
                                    </label>
                                </div>
                                
                                <div class="mos-settings-option">
                                    <button class="mos-button mos-button-primary" id="${windowId}-save-system">
                                        Save Changes
                                    </button>
                                </div>
                                
                                <div class="mos-settings-section" style="margin-top: 30px;">
                                    <h3 class="mos-settings-section-title">System Maintenance</h3>
                                    
                                    <div class="mos-settings-option">
                                        <button class="mos-button mos-button-secondary" id="${windowId}-clear-cache">
                                            Clear Cache
                                        </button>
                                    </div>
                                    
                                    <div class="mos-settings-option">
                                        <button class="mos-button mos-button-secondary" id="${windowId}-restart">
                                            Restart System
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
                        
                        // Set initial values
                        document.getElementById(`${windowId}-setting-debug`).checked = 
                            this.kernel.config.system.debug === true;
                        document.getElementById(`${windowId}-setting-auto-login`).checked = 
                            this.kernel.config.user.autoLogin === true;
                        
                        // Save button
                        document.getElementById(`${windowId}-save-system`).addEventListener('click', async () => {
                            try {
                                // Get values
                                const debug = document.getElementById(`${windowId}-setting-debug`).checked;
                                const autoLogin = document.getElementById(`${windowId}-setting-auto-login`).checked;
                                
                                // Save to config
                                await this.kernel.services.get('system').call('updateConfig', {
                                    key: 'system.debug',
                                    value: debug
                                });
                                
                                await this.kernel.services.get('system').call('updateConfig', {
                                    key: 'user.autoLogin',
                                    value: autoLogin
                                });
                                
                                // Apply changes
                                this.kernel.config.system.debug = debug;
                                this.kernel.config.user.autoLogin = autoLogin;
                                this.kernel.state.debug = debug;
                                
                                // Show notification
                                this.kernel.modules.ui.showNotification(
                                    'Settings Saved',
                                    'System settings have been updated',
                                    3000
                                );
                            } catch (error) {
                                this.kernel.modules.ui.showNotification(
                                    'Error',
                                    `Failed to save settings: ${error.message}`,
                                    5000
                                );
                            }
                        });
                        
                        // Clear cache button
                        document.getElementById(`${windowId}-clear-cache`).addEventListener('click', async () => {
                            try {
                                // Show notification
                                this.kernel.modules.ui.showNotification(
                                    'Cache Cleared',
                                    'System cache has been cleared',
                                    3000
                                );
                            } catch (error) {
                                this.kernel.modules.ui.showNotification(
                                    'Error',
                                    `Failed to clear cache: ${error.message}`,
                                    5000
                                );
                            }
                        });
                        
                        // Restart button
                        document.getElementById(`${windowId}-restart`).addEventListener('click', () => {
                            if (confirm('Are you sure you want to restart the system?')) {
                                window.location.reload();
                            }
                        });
                        break;
                        
                    case 'about':
                        // Get system info
                        const systemInfo = await this.kernel.services.get('system').call('getSystemInfo', {});
                        
                        content.innerHTML = `
                            <div class="mos-settings-section">
                                <h2 class="mos-settings-section-title">About MOS</h2>
                                
                                <div style="text-align: center; margin-bottom: 20px;">
                                    <img src="mos.php?file=/system/logo.svg" alt="MOS Logo" style="width: 100px; height: 100px;">
                                    <h3 style="margin-top: 10px;">MOS - My Operating System</h3>
                                    <div>Version ${systemInfo.version} (Build ${systemInfo.build})</div>
                                </div>
                                
                                <div class="mos-settings-option">
                                    <label class="mos-settings-label">System Information</label>
                                    <div style="background: #333; padding: 10px; border-radius: 4px;">
                                        <div>Server Software: ${systemInfo.server}</div>
                                        <div>PHP Version: ${systemInfo.php_version}</div>
                                        <div>Uptime: ${Math.floor(systemInfo.uptime / 60)} minutes</div>
                                        <div>Debug Mode: ${systemInfo.debug_mode ? 'Enabled' : 'Disabled'}</div>
                                    </div>
                                </div>
                                
                                <div class="mos-settings-option" style="margin-top: 20px;">
                                    <div style="text-align: center; color: #ccc;">
                                        &copy; 2025 MOS Team<br>
                                        All rights reserved.
                                    </div>
                                </div>
                            </div>
                        `;
                        break;
                        
                    default:
                        content.innerHTML = `
                            <div class="mos-settings-section">
                                <h2 class="mos-settings-section-title">${section.charAt(0).toUpperCase() + section.slice(1)} Settings</h2>
                                <p>Settings for this section are not yet implemented.</p>
                            </div>
                        `;
                }
            }
        }
        
        /**
         * UI Manager
         * Manages user interface components
         */
        class UIManager {
            /**
             * Create a new UI manager
             * @param {MOSKernel} kernel - Kernel reference
             */
            constructor(kernel) {
                this.kernel = kernel;
                this.log = kernel._createLogger('ui');
                
                this.log.info('UI manager initialized');
            }
            
            /**
             * Initialize UI manager
             * @async
             */
            async initialize() {
                // Apply theme
                this.applyTheme(this.kernel.config.ui.theme || 'dark');
                
                // Apply font size
                this.applyFontSize(this.kernel.config.ui.fontSize || 'medium');
                
                return true;
            }
            
            /**
             * Apply theme
             * @param {string} theme - Theme name
             */
            applyTheme(theme) {
                document.body.className = `mos-theme-${theme}`;

                // Update theme stylesheet if present
                const themeLink = document.getElementById('theme-stylesheet');
                if (themeLink) {
                    themeLink.href = `mos.php?file=/system/themes/${theme}.css`;
                }

                this.log.info(`Applied theme: ${theme}`);
            }
            
            /**
             * Apply font size
             * @param {string} size - Font size (small, medium, large)
             */
            applyFontSize(size) {
                const sizes = {
                    small: '14px',
                    medium: '16px',
                    large: '18px'
                };
                
                document.documentElement.style.fontSize = sizes[size] || sizes.medium;
                
                this.log.info(`Applied font size: ${size}`);
            }
            
            /**
             * Show a notification
             * @param {string} title - Notification title
             * @param {string} message - Notification message
             * @param {number} [duration=5000] - Display duration in milliseconds
             */
            showNotification(title, message, duration = 5000) {
                const container = document.getElementById('mos-notification-container');
                
                // Create notification element
                const notification = document.createElement('div');
                notification.className = 'mos-notification';
                notification.innerHTML = `
                    <div class="mos-notification-title">${title}</div>
                    <div class="mos-notification-body">${message}</div>
                `;
                
                // Add to container
                container.appendChild(notification);
                
                // Show notification with animation
                setTimeout(() => {
                    notification.classList.add('show');
                }, 10);
                
                // Remove after duration
                setTimeout(() => {
                    notification.classList.remove('show');
                    
                    // Remove from DOM after animation
                    setTimeout(() => {
                        if (notification.parentNode) {
                            notification.remove();
                        }
                    }, 300);
                }, duration);
                
                return notification;
            }
            
            /**
             * Show a dialog
             * @param {string} title - Dialog title
             * @param {string} message - Dialog message
             * @param {Object} [options] - Dialog options
             * @returns {Promise<string>} Selected button
             */
            showDialog(title, message, options = {}) {
                return new Promise(resolve => {
                    // Default options
                    const defaultOptions = {
                        buttons: ['OK'],
                        defaultButton: 'OK',
                        cancelButton: null
                    };
                    
                    const dialogOptions = { ...defaultOptions, ...options };
                    
                    // Create backdrop
                    const backdrop = document.createElement('div');
                    backdrop.className = 'mos-modal-backdrop';
                    
                    // Create dialog
                    const dialog = document.createElement('div');
                    dialog.className = 'mos-modal';
                    
                    // Build dialog content
                    dialog.innerHTML = `
                        <div class="mos-modal-header">
                            <div class="mos-modal-title">${title}</div>
                        </div>
                        <div class="mos-modal-body">
                            ${message}
                        </div>
                        <div class="mos-modal-footer">
                            ${dialogOptions.buttons.map(button => `
                                <button class="mos-button ${button === dialogOptions.defaultButton ? 'mos-button-primary' : 'mos-button-secondary'}" data-button="${button}">
                                    ${button}
                                </button>
                            `).join('')}
                        </div>
                    `;
                    
                    // Add to DOM
                    backdrop.appendChild(dialog);
                    document.body.appendChild(backdrop);
                    
                    // Show dialog with animation
                    setTimeout(() => {
                        backdrop.classList.add('show');
                    }, 10);
                    
                    // Set up button handlers
                    dialog.querySelectorAll('.mos-button').forEach(button => {
                        button.addEventListener('click', () => {
                            const buttonName = button.getAttribute('data-button');
                            
                            // Hide dialog
                            backdrop.classList.remove('show');
                            
                            // Remove from DOM after animation
                            setTimeout(() => {
                                if (backdrop.parentNode) {
                                    backdrop.remove();
                                }
                                
                                resolve(buttonName);
                            }, 300);
                        });
                    });
                    
                    // Handle Escape key
                    if (dialogOptions.cancelButton) {
                        document.addEventListener('keydown', function escHandler(e) {
                            if (e.key === 'Escape') {
                                document.removeEventListener('keydown', escHandler);
                                
                                // Hide dialog
                                backdrop.classList.remove('show');
                                
                                // Remove from DOM after animation
                                setTimeout(() => {
                                    if (backdrop.parentNode) {
                                        backdrop.remove();
                                    }
                                    
                                    resolve(dialogOptions.cancelButton);
                                }, 300);
                            }
                        });
                    }
                });
            }
        }
        
        // Initialize the kernel when the DOM is loaded
        document.addEventListener('DOMContentLoaded', async () => {
            try {
                // Create kernel instance
                window.kernel = new MOSKernel();
                
                // Initialize kernel
                await window.kernel.initialize();
            } catch (error) {
                console.error('Failed to initialize MOS:', error);
                
                // Show error screen
                const splashScreen = document.getElementById('mos-splash-screen');
                if (splashScreen) {
                    splashScreen.style.display = 'none';
                }
                
                const errorScreen = document.getElementById('mos-error-screen');
                if (errorScreen) {
                    const errorTitle = document.getElementById('error-title');
                    const errorMessage = document.getElementById('error-message');
                    const errorDetails = document.getElementById('error-details');
                    
                    errorTitle.textContent = 'System Initialization Failed';
                    errorMessage.textContent = error.message;
                    
                    if (error.stack) {
                        errorDetails.textContent = error.stack;
                        errorDetails.style.display = 'block';
                    }
                    
                    errorScreen.style.display = 'flex';
                }
            }
        });
    </script>
</body>
</html>
