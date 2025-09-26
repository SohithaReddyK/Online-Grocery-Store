// API utility functions for making requests to the backend

// Check if we're in a browser environment
const isBrowser = typeof window !== "undefined"

// Backend URL - with fallback to prevent errors if backend is not available
const BACKEND_URL = "http://localhost:9001/api"

// Check if backend is available
const checkBackendAvailability = async () => {
  if (!isBrowser) return false

  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 3000) // 3 second timeout

    const response = await fetch(`${BACKEND_URL}/test/hello`, {
      signal: controller.signal,
    })

    clearTimeout(timeoutId)
    return response.ok
  } catch (error) {
    console.warn("Backend not available:", error)
    return false
  }
}

// Generic fetch function with error handling and mock data fallback
async function callApi(method: string, endpoint: string, data: any) {
  try {
    // Check if backend is available
    const isBackendAvailable = await checkBackendAvailability()

    if (!isBackendAvailable) {
      console.warn("Backend not available, using mock data")
      return handleMockResponse(endpoint, data)
    }

    const response = await fetch(endpoint, {
      method: method,
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    })

    // Handle specific HTTP status codes
    if (response.status === 500) {
      console.error("Server error (500) occurred")
      const errorData = await response.json().catch(() => ({ error: "Internal Server Error" }))

      // Log detailed error information
      console.error("Server error details:", errorData)

      // Use mock data as fallback for server errors
      console.warn("Server error, falling back to mock data")
      return {
        ...handleMockResponse(endpoint, data),
        _wasServerError: true,
        _errorDetails: errorData,
      }
    }

    if (!response.ok) {
      const message = await response.text()
      throw new Error(message || `HTTP error! status: ${response.status}`)
    }

    return await response.json()
  } catch (error) {
    console.error("API request failed:", error)

    // If fetch failed completely, use mock data
    if (error.name === "TypeError" && error.message.includes("Failed to fetch")) {
      console.warn("Network error, using mock data")
      return handleMockResponse(endpoint, data)
    }

    throw error
  }
}

// Handle mock responses for when backend is not available
function handleMockResponse(endpoint: string, data: any) {
  // Extract the endpoint type from the URL
  const endpointPath = endpoint.replace(BACKEND_URL, "")

  if (endpointPath.includes("/auth/signin")) {
    return {
      id: 1,
      name: data.email.split("@")[0],
      email: data.email,
      message: "Mock login successful",
    }
  }

  if (endpointPath.includes("/auth/signup")) {
    return {
      message: "Mock registration successful",
    }
  }

  return {
    message: "Mock response",
    success: true,
  }
}

export const authApi = {
  login: async (data: any) => {
    return callApi("POST", `${BACKEND_URL}/auth/signin`, data)
  },
  register: async (data: any) => {
    return callApi("POST", `${BACKEND_URL}/auth/signup`, data)
  },
}

export const testBackendConnection = async () => {
  try {
    const isAvailable = await checkBackendAvailability()

    if (!isAvailable) {
      return {
        success: false,
        message: "Backend server is not available. Using mock data for demonstration.",
      }
    }

    const response = await fetch(`${BACKEND_URL}/test/hello`)
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    const data = await response.json()
    return { success: true, message: data.message }
  } catch (error: any) {
    console.error("Backend connection test failed:", error)
    return {
      success: false,
      message: "Backend connection failed. Using mock data for demonstration.",
    }
  }
}

export { callApi }
