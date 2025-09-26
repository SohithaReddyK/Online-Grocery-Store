"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { CheckCircle, Package, MapPin, CreditCard, Clock, Home } from "lucide-react"
import Link from "next/link"

interface CartItem {
  id: number
  name: string
  price: number
  image: string
  quantity: number
}

interface OrderDetails {
  items: CartItem[]
  deliveryAddress: string
  paymentMethod: string
  total: string
  orderDate: string
  orderId: string
}

export default function OrderConfirmationPage() {
  const [orderDetails, setOrderDetails] = useState<OrderDetails | null>(null)

  const USD_TO_INR = 83
  const DELIVERY_FEE_INR = 49

  const formatPrice = (usdPrice: number) =>
    new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR" }).format(usdPrice * USD_TO_INR)

  useEffect(() => {
    const details = localStorage.getItem("orderDetails")
    if (details) {
      setOrderDetails(JSON.parse(details))
    }
  }, [])

  const getEstimatedDelivery = () => {
    const orderDate = new Date(orderDetails?.orderDate || "")
    const deliveryDate = new Date(orderDate)
    const daysToAdd = orderDetails?.paymentMethod === "cod" ? 4 : 3
    deliveryDate.setDate(deliveryDate.getDate() + daysToAdd)
    return deliveryDate.toLocaleDateString("en-IN", {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric",
    })
  }

  const getPaymentMethodDisplay = () => {
    if (orderDetails?.paymentMethod === "cod") return "Cash on Delivery"
    return "Online Payment"
  }

  const getTotalItems = () => {
    return orderDetails?.items.reduce((total, item) => total + item.quantity, 0) || 0
  }

  const getSubtotalUSD = () => {
    return orderDetails?.items.reduce((total, item) => total + item.price * item.quantity, 0) || 0
  }

  if (!orderDetails) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>No Order Found</CardTitle>
            <CardDescription>Unable to find order details</CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Link href="/dashboard">
              <Button>Continue Shopping</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <h1 className="text-2xl font-bold text-primary">GroceryStore</h1>
            <Link href="/dashboard">
              <Button variant="outline" size="sm">
                <Home className="h-4 w-4 mr-2" />
                Continue Shopping
              </Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Success Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <CheckCircle className="h-16 w-16 text-green-500" />
          </div>
          <h2 className="text-3xl font-bold text-foreground mb-2">Order Confirmed!</h2>
          <p className="text-muted-foreground">
            Thank you for your order. We'll get it ready for delivery.
          </p>
          <div className="mt-4">
            <Badge variant="secondary" className="text-lg px-4 py-2">
              Order ID: {orderDetails.orderId}
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Order Details */}
          <div className="lg:col-span-2 space-y-6">
            {/* Order Summary */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Package className="h-5 w-5 mr-2" />
                  Order Summary
                </CardTitle>
                <CardDescription>{getTotalItems()} items purchased</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {orderDetails.items.map((item) => (
                    <div key={item.id} className="flex items-center space-x-4">
                      <div className="w-16 h-16 rounded-lg overflow-hidden bg-muted">
                        <img
                          src={item.image || "/placeholder.svg"}
                          alt={item.name}
                          className="w-full h-full object-cover"
                        />
                      </div>
                      <div className="flex-1">
                        <h4 className="font-semibold">{item.name}</h4>
                        <p className="text-sm text-muted-foreground">Quantity: {item.quantity}</p>
                      </div>
                      <div className="text-right">
                        <p className="font-semibold">
                          {formatPrice(item.price * item.quantity)}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {formatPrice(item.price)} each
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Delivery Address */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <MapPin className="h-5 w-5 mr-2" />
                  Delivery Address
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-foreground">{orderDetails.deliveryAddress}</p>
              </CardContent>
            </Card>

            {/* Payment Method */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <CreditCard className="h-5 w-5 mr-2" />
                  Payment Method
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <span>{getPaymentMethodDisplay()}</span>
                  <Badge variant={orderDetails.paymentMethod === "cod" ? "secondary" : "default"}>
                    {orderDetails.paymentMethod === "cod" ? "Pay on Delivery" : "Paid"}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Order Info Sidebar */}
          <div className="space-y-6">
            {/* Total Cost */}
            <Card>
              <CardHeader>
                <CardTitle>Total Cost</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span>Subtotal</span>
                    <span>{formatPrice(getSubtotalUSD())}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Delivery Fee</span>
                    <span>{formatPrice(DELIVERY_FEE_INR / USD_TO_INR)}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between font-bold text-lg">
                    <span>Total</span>
                    <span>{orderDetails.total}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Estimated Delivery */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Clock className="h-5 w-5 mr-2" />
                  Estimated Delivery
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="text-lg font-semibold text-primary">{getEstimatedDelivery()}</div>
                  <div className="text-sm text-muted-foreground">
                    {orderDetails.paymentMethod === "cod"
                      ? "COD orders may take 1-2 additional business days"
                      : "Standard delivery within 2-3 business days"}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    You'll receive tracking information via email once your order ships.
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Order Status */}
            <Card>
              <CardHeader>
                <CardTitle>Order Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    <span className="text-sm">Order Confirmed</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-muted rounded-full"></div>
                    <span className="text-sm text-muted-foreground">Preparing Order</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-muted rounded-full"></div>
                    <span className="text-sm text-muted-foreground">Out for Delivery</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 bg-muted rounded-full"></div>
                    <span className="text-sm text-muted-foreground">Delivered</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Actions */}
            <div className="space-y-3">
              <Link href="/dashboard">
                <Button className="w-full">Continue Shopping</Button>
              </Link>
              <Button variant="outline" className="w-full bg-transparent">
                Track Order
              </Button>
            </div>
          </div>
        </div>

        {/* Additional Information */}
        <div className="mt-12 text-center">
          <Card>
            <CardContent className="pt-6">
              <h3 className="font-semibold mb-2">Need Help?</h3>
              <p className="text-sm text-muted-foreground mb-4">
                If you have any questions about your order, please contact our customer support.
              </p>
              <div className="flex justify-center space-x-4">
                <Button variant="outline" size="sm" className="bg-transparent">
                  Contact Support
                </Button>
                <Button variant="outline" size="sm" className="bg-transparent">
                  Order History
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}
