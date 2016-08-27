//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Web.Mvc;

//namespace SellYourFace.Controllers
//{
//    [Authorize]
//    public class Raffle : Controller
//    {
//        Dictionary<int, string> entries = new Dictionary<int, string>();

//        public ActionResult Index()
//        {
//            return View();
//        }

//        public string CalculateRaffle()
//        {
//            StuffEntries();
//            Random random = new Random();
//            int randNum = random.Next(0, entries.Count + 1);
//            string theResult = entries[randNum];



//            return theResult;
//        }

//        public ActionResult CalActionResult()
//        {
//            return CalActionResult();
//        }

//        private void StuffEntries()
//        {
//            entries.Add(2344, "Patrick Fool");
//            entries.Add(1769, "Ron Jenkins");
//            entries.Add(4591, "Johan Pete R Queen");
//            entries.Add(2222, "Fuck R Face");
//            entries.Add(3218, "James Heat");
//            entries.Add(1369, "Brian McLaughlin");
//            entries.Add(4597, "Matt Powelson");
//            entries.Add(1759, "Anfield Mod");
//            entries.Add(4594, "Chuck E Cheeze");
//            entries.Add(1234, "Jack Her Jill");
//            entries.Add(1235, "Steve");
//            entries.Add(1236, "Jo");
//            entries.Add(1237, "Jammer");
//        }
//    }
//}