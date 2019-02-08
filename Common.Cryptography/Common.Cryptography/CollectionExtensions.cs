using System.Collections.Generic;

namespace Common.Cryptography
{
	public static class CollectionExtensions
	{
		public static IEnumerable<T> Combine<T>(this IEnumerable<T> list1, IEnumerable<T> list2)
		{
			foreach (var item in list1)
				yield return item;
			foreach (var item in list2)
				yield return item;
		}
	}
}