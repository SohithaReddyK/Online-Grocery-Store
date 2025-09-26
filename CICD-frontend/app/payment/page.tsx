"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { ArrowLeft, CreditCard, Smartphone, Wallet, Banknote, QrCode } from "lucide-react"
import Link from "next/link"

interface CartItem {
  id: number
  name: string
  price: number
  image: string
  quantity: number
}

export default function PaymentPage() {
  const [cartItems, setCartItems] = useState<CartItem[]>([])
  const [deliveryAddress, setDeliveryAddress] = useState("")
  const [paymentMethod, setPaymentMethod] = useState("")
  const [cardDetails, setCardDetails] = useState({
    number: "",
    expiry: "",
    cvv: "",
    name: "",
  })

  const USD_TO_INR = 83
  const DELIVERY_FEE_INR = 49

  const formatPrice = (usdPrice: number) =>
    new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR" }).format(usdPrice * USD_TO_INR)

  useEffect(() => {
    const existingCart = JSON.parse(localStorage.getItem("cart") || "[]")
    const address = localStorage.getItem("deliveryAddress") || ""
    setCartItems(existingCart)
    setDeliveryAddress(address)
  }, [])

  const getSubtotalUSD = () => {
    return cartItems.reduce((total, item) => total + item.price * item.quantity, 0)
  }

  const getTotalItems = () => {
    return cartItems.reduce((total, item) => total + item.quantity, 0)
  }

  const getTotalUSD = () => {
    return getSubtotalUSD() + DELIVERY_FEE_INR / USD_TO_INR
  }

  const handlePayment = () => {
    if (!paymentMethod) {
      alert("Please select a payment method")
      return
    }

    if (
      paymentMethod === "online" &&
      (!cardDetails.number || !cardDetails.expiry || !cardDetails.cvv || !cardDetails.name)
    ) {
      alert("Please fill in all card details")
      return
    }

    const orderDetails = {
      items: cartItems,
      deliveryAddress,
      paymentMethod,
      total: formatPrice(getTotalUSD()),
      orderDate: new Date().toISOString(),
      orderId: Math.random().toString(36).substr(2, 9).toUpperCase(),
    }

    localStorage.setItem("orderDetails", JSON.stringify(orderDetails))
    localStorage.removeItem("cart")
    localStorage.removeItem("deliveryAddress")
    window.location.href = "/order-confirmation"
  }

  if (cartItems.length === 0) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>No Items to Pay For</CardTitle>
            <CardDescription>Your cart is empty</CardDescription>
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
            <div className="flex items-center">
              <Link href="/cart">
                <Button variant="ghost" size="sm" className="mr-4">
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Back to Cart
                </Button>
              </Link>
              <h1 className="text-2xl font-bold text-primary">GroceryStore</h1>
            </div>
            <div className="text-sm text-muted-foreground">Step 2 of 2: Payment</div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-foreground mb-2">Payment</h2>
          <p className="text-muted-foreground">Choose your preferred payment method</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Payment Methods */}
          <div className="lg:col-span-2 space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Select Payment Method</CardTitle>
                <CardDescription>Choose how you'd like to pay for your order</CardDescription>
              </CardHeader>
              <CardContent>
                <RadioGroup value={paymentMethod} onValueChange={setPaymentMethod}>
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2 p-4 border rounded-lg">
                      <RadioGroupItem value="online" id="online" />
                      <Label htmlFor="online" className="flex-1 cursor-pointer">
                        <div className="flex items-center space-x-3">
                          <div className="flex space-x-2">
                            <QrCode className="h-5 w-5 text-primary" />
                            <CreditCard className="h-5 w-5 text-primary" />
                            <Smartphone className="h-5 w-5 text-primary" />
                            <Wallet className="h-5 w-5 text-primary" />
                          </div>
                          <div>
                            <div className="font-semibold">QR Code Scanner / Online Payment</div>
                            <div className="text-sm text-muted-foreground">UPI, Card, Netbanking, Wallet</div>
                          </div>
                        </div>
                      </Label>
                    </div>

                    <div className="flex items-center space-x-2 p-4 border rounded-lg">
                      <RadioGroupItem value="cod" id="cod" />
                      <Label htmlFor="cod" className="flex-1 cursor-pointer">
                        <div className="flex items-center space-x-3">
                          <Banknote className="h-5 w-5 text-primary" />
                          <div>
                            <div className="font-semibold">Cash on Delivery (COD)</div>
                            <div className="text-sm text-muted-foreground">Pay when your order arrives</div>
                          </div>
                        </div>
                      </Label>
                    </div>
                  </div>
                </RadioGroup>
              </CardContent>
            </Card>

            {paymentMethod === "online" && (
              <Card>
                <CardHeader>
                  <CardTitle>Payment Details</CardTitle>
                  <CardDescription>Enter your payment information</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 gap-4">
                    <div>
                      <Label htmlFor="cardName">Cardholder Name</Label>
                      <Input
                        id="cardName"
                        placeholder="John Doe"
                        value={cardDetails.name}
                        onChange={(e) => setCardDetails({ ...cardDetails, name: e.target.value })}
                      />
                    </div>
                    <div>
                      <Label htmlFor="cardNumber">Card Number</Label>
                      <Input
                        id="cardNumber"
                        placeholder="1234 5678 9012 3456"
                        value={cardDetails.number}
                        onChange={(e) => setCardDetails({ ...cardDetails, number: e.target.value })}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="expiry">Expiry Date</Label>
                        <Input
                          id="expiry"
                          placeholder="MM/YY"
                          value={cardDetails.expiry}
                          onChange={(e) => setCardDetails({ ...cardDetails, expiry: e.target.value })}
                        />
                      </div>
                      <div>
                        <Label htmlFor="cvv">CVV</Label>
                        <Input
                          id="cvv"
                          placeholder="123"
                          value={cardDetails.cvv}
                          onChange={(e) => setCardDetails({ ...cardDetails, cvv: e.target.value })}
                        />
                      </div>
                    </div>
                  </div>

                  <Separator />

                  <div className="space-y-3">
                    <h4 className="font-semibold">Alternative Payment Methods</h4>
                    <div className="grid grid-cols-2 gap-3">
                      <Button variant="outline" className="justify-start bg-transparent">
                        <Smartphone className="h-4 w-4 mr-2" />
                        UPI Payment
                      </Button>
                      <Button variant="outline" className="justify-start bg-transparent">
                        <Wallet className="h-4 w-4 mr-2" />
                        Digital Wallet
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {paymentMethod === "cod" && (
              <Card>
                <CardHeader>
                  <CardTitle>Cash on Delivery</CardTitle>
                  <CardDescription>Payment information</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center space-x-2 text-sm">
                      <Banknote className="h-4 w-4 text-primary" />
                      <span>Pay {formatPrice(getTotalUSD())} when your order arrives</span>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Please keep exact change ready for faster delivery
                    </div>
                    <div className="text-sm text-muted-foreground">
                      COD orders may take 1-2 additional business days for processing
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Order Summary */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Order Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  {cartItems.slice(0, 3).map((item) => (
                    <div key={item.id} className="flex justify-between text-sm">
                      <span>
                        {item.name} x{item.quantity}
                      </span>
                      <span>{formatPrice(item.price * item.quantity)}</span>
                    </div>
                  ))}
                  {cartItems.length > 3 && (
                    <div className="text-sm text-muted-foreground">+{cartItems.length - 3} more items</div>
                  )}
                </div>
                <Separator />
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span>Subtotal ({getTotalItems()} items)</span>
                    <span>{formatPrice(getSubtotalUSD())}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Delivery Fee</span>
                    <span>{formatPrice(DELIVERY_FEE_INR / USD_TO_INR)}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between font-bold text-lg">
                    <span>Total</span>
                    <span>{formatPrice(getTotalUSD())}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Delivery Address</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{deliveryAddress}</p>
              </CardContent>
            </Card>

            <Button className="w-full" size="lg" onClick={handlePayment} disabled={!paymentMethod}>
              {paymentMethod === "cod" ? "Place Order (COD)" : "Pay Now"}
            </Button>
          </div>
        </div>
      </main>
    </div>
  )
}
