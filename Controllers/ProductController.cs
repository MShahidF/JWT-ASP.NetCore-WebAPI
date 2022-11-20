using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using JWT_ASP.NetCore_WebAPI.Models;
using JWT_ASP.NetCore_WebAPI.Repositories;

namespace JWT_ASP.NetCore_WebAPI.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class ProductController : ControllerBase
  {
    [HttpGet]
    [Authorize]
    public IActionResult GetAllProducts()
    {
      try
      {
        var products = ProductRepository.Products.ToList();

        return Ok(products);
      }
      catch (Exception ex)
      {
        return StatusCode(500, ex.Message);
      }
    }

    [HttpGet("{id}")]
    [Authorize]
    public IActionResult GetProductById(Guid id)
    {
      try
      {
        var product = ProductRepository.Products.FirstOrDefault(option => option.ProductId == id);

        if (product is null)
        {
          return NotFound();
        }

        return Ok(product);
      }
      catch (Exception ex)
      {
        return StatusCode(500, ex.Message);
      }
    }

    [HttpPost]
    [Authorize]
    public IActionResult CreateProduct([FromBody] Product product)
    {
      try
      {
        ProductRepository.Products.Add(product);

        return Ok();
      }
      catch (Exception ex)
      {
        return StatusCode(500, ex.Message);
      }
    }

    [HttpPut("{id}")]
    [Authorize(Roles = "Administrator")]
    public IActionResult UpdateProduct(Guid id, [FromBody] Product product)
    {
      try
      {
        var oldProduct = ProductRepository.Products.FirstOrDefault(option => option.ProductId == id);

        if (oldProduct is null)
        {
          return NotFound();
        }

        var indexOf = ProductRepository.Products.IndexOf(oldProduct);

        ProductRepository.Products[indexOf].ProductName = product.ProductName;
        ProductRepository.Products[indexOf].ProductPrice = product.ProductPrice;

        return NoContent();

      }
      catch (Exception ex)
      {
        return StatusCode(500, ex.Message);
      }
    }

    [HttpDelete("{id}")]
    [Authorize(Roles = "Administrator")]
    public IActionResult DeleteProduct(Guid id)
    {
      try
      {
        var product = ProductRepository.Products.FirstOrDefault(option => option.ProductId == id);

        if (product is null)
        {
          return NotFound();
        }

        ProductRepository.Products.Remove(product);

        return NoContent();
      }
      catch (Exception ex)
      {
        return StatusCode(500, ex.Message);
      }
    }
  }
}
