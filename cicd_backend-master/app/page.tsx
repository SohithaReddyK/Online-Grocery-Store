import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { ChefHat, Search, UtensilsCrossed, Briefcase } from "lucide-react"

export default function Home() {
  return (
    <div className="flex flex-col min-h-screen">
      <header className="sticky top-0 z-10 bg-white border-b">
        <div className="container flex items-center justify-between h-16 px-4 md:px-6">
          <div className="flex items-center gap-2">
            <ChefHat className="w-6 h-6 text-orange-500" />
            <span className="text-xl font-bold">FoodPath</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/search">
              <Button variant="ghost" size="icon">
                <Search className="w-5 h-5" />
                <span className="sr-only">Search</span>
              </Button>
            </Link>
            <Link href="/auth">
              <Button className="bg-orange-500 hover:bg-orange-600">Login</Button>
            </Link>
          </div>
        </div>
      </header>
      <main className="flex-1">
        <section className="relative h-[500px] bg-gradient-to-r from-orange-100 to-orange-50">
          <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1495521821757-a1efb6729352?q=80&w=1000&auto=format&fit=crop')] bg-cover bg-center opacity-20" />
          <div className="container relative flex flex-col items-center justify-center h-full px-4 py-12 text-center md:px-6">
            <h1 className="text-4xl font-bold tracking-tight sm:text-5xl md:text-6xl">
              Welcome to <span className="text-orange-500">FoodPath</span>
            </h1>
            <p className="max-w-[600px] mt-4 text-lg text-gray-600 md:text-xl">
              Discover, create, and share amazing recipes from around the world
            </p>
            <div className="flex flex-col gap-4 mt-8 sm:flex-row">
              <Link href="/recipes">
                <Button className="bg-orange-500 hover:bg-orange-600">Browse Recipes</Button>
              </Link>
              <Link href="/auth?signup=true">
                <Button variant="outline" className="border-orange-500 text-orange-500 hover:bg-orange-50">
                  Join Now
                </Button>
              </Link>
            </div>
          </div>
        </section>
        <section className="py-12 bg-white">
          <div className="container px-4 md:px-6">
            <h2 className="text-3xl font-bold text-center">Popular Categories</h2>
            <div className="grid grid-cols-2 gap-4 mt-8 md:grid-cols-4">
              {categories.map((category) => (
                <Link key={category.name} href={`/recipes/${category.slug}`}>
                  <div className="relative overflow-hidden transition-transform rounded-lg group hover:scale-105">
                    <div className="aspect-square bg-orange-100">
                      <Image
                        src={category.image || "/placeholder.svg"}
                        alt={category.name}
                        width={300}
                        height={300}
                        className="object-cover w-full h-full"
                      />
                    </div>
                    <div className="absolute inset-0 flex items-center justify-center bg-black/40">
                      <h3 className="text-xl font-bold text-white">{category.name}</h3>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </section>
        <section className="py-12 bg-orange-50">
          <div className="container px-4 md:px-6">
            <h2 className="text-3xl font-bold text-center mb-8">Explore by Cuisine</h2>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4 lg:grid-cols-6">
              {cuisines.map((cuisine) => (
                <Link key={cuisine.name} href={`/recipes/cuisine/${cuisine.slug}`}>
                  <div className="relative overflow-hidden transition-transform rounded-full group hover:scale-105">
                    <div className="aspect-square bg-orange-100">
                      <Image
                        src={cuisine.image || "/placeholder.svg"}
                        alt={cuisine.name}
                        width={200}
                        height={200}
                        className="object-cover w-full h-full rounded-full"
                      />
                    </div>
                    <div className="absolute inset-0 flex items-center justify-center bg-black/30 rounded-full">
                      <h3 className="text-lg font-bold text-white">{cuisine.name}</h3>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </section>
        <section className="py-12 bg-white">
          <div className="container px-4 md:px-6">
            <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
              <div className="max-w-md">
                <h2 className="text-3xl font-bold">Share Your Culinary Creations</h2>
                <p className="mt-4 text-gray-600">
                  Join our community of food enthusiasts and share your favorite recipes with the world.
                </p>
                <Link href="/submit-recipe">
                  <Button className="mt-6 bg-orange-500 hover:bg-orange-600">Submit a Recipe</Button>
                </Link>
              </div>
              <div className="relative w-full max-w-md mt-8 md:mt-0">
                <div className="aspect-video overflow-hidden rounded-lg">
                  <Image
                    src="https://images.unsplash.com/photo-1556911220-bda9f7f7597e?q=80&w=1000&auto=format&fit=crop"
                    alt="Cooking"
                    width={500}
                    height={300}
                    className="object-cover w-full h-full"
                  />
                </div>
                <div className="absolute -bottom-4 -right-4 p-4 bg-white rounded-lg shadow-lg">
                  <UtensilsCrossed className="w-8 h-8 text-orange-500" />
                </div>
              </div>
            </div>
          </div>
        </section>
        <section className="py-12 bg-orange-50">
          <div className="container px-4 md:px-6">
            <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
              <div className="relative w-full max-w-md mt-8 md:mt-0 order-2 md:order-1">
                <div className="aspect-video overflow-hidden rounded-lg">
                  <Image
                    src="https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?q=80&w=1000&auto=format&fit=crop"
                    alt="Job Portal"
                    width={500}
                    height={300}
                    className="object-cover w-full h-full"
                  />
                </div>
                <div className="absolute -bottom-4 -left-4 p-4 bg-white rounded-lg shadow-lg">
                  <Briefcase className="w-8 h-8 text-orange-500" />
                </div>
              </div>
              <div className="max-w-md order-1 md:order-2">
                <h2 className="text-3xl font-bold">Looking for a Job?</h2>
                <p className="mt-4 text-gray-600">
                  Check out our job portal to find career opportunities in the food industry and beyond.
                </p>
                <Link href="/job-portal">
                  <Button className="mt-6 bg-orange-500 hover:bg-orange-600">Visit Job Portal</Button>
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
      <footer className="py-6 bg-orange-500 text-white">
        <div className="container px-4 md:px-6">
          <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
            <div className="flex items-center gap-2">
              <ChefHat className="w-6 h-6" />
              <span className="text-xl font-bold">FoodPath</span>
            </div>
            <p className="text-sm text-orange-100">© 2024 FoodPath. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

const categories = [
  {
    name: "Diet Recipes",
    slug: "diet",
    image: "https://images.unsplash.com/photo-1546069901-ba9599a7e63c?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Home Recipes",
    slug: "home",
    image: "https://images.unsplash.com/photo-1513104890138-7c749659a591?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Healthy Recipes",
    slug: "healthy",
    image: "https://images.unsplash.com/photo-1540420773420-3366772f4999?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Gym Recipes",
    slug: "gym",
    image: "https://images.unsplash.com/photo-1565299543923-37dd37887442?q=80&w=1000&auto=format&fit=crop",
  },
]

const cuisines = [
  {
    name: "Indian",
    slug: "indian",
    image: "https://images.unsplash.com/photo-1585937421612-70a008356c36?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Italian",
    slug: "italian",
    image: "https://images.unsplash.com/photo-1551183053-bf91a1d81141?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Chinese",
    slug: "chinese",
    image: "https://images.unsplash.com/photo-1563245372-f21724e3856d?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Mexican",
    slug: "mexican",
    image: "https://images.unsplash.com/photo-1565299585323-38d6b0865b47?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Thai",
    slug: "thai",
    image: "https://images.unsplash.com/photo-1559847844-5315695dadae?q=80&w=1000&auto=format&fit=crop",
  },
  {
    name: "Mediterranean",
    slug: "mediterranean",
    image: "https://images.unsplash.com/photo-1512621776951-a57141f2eefd?q=80&w=1000&auto=format&fit=crop",
  },
]
