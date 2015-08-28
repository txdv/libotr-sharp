//  Copyright (c) 2015 Andrius Bentkus
//
//  This library is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as
//  published by the Free Software Foundation; either version 2.1 of the
//  License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Otr
{
    static class Assign
    {
        static void MethodsToDelegatesSetFields(IEnumerable<Tuple<MethodInfo, FieldInfo>> pairs, object source, object destination)
        {
            foreach (var tuple in pairs) {
                var method = tuple.Item1;
                var field = tuple.Item2;

                var fieldType = field.FieldType;

                try {
                    if (!fieldType.GetMethod("Invoke").SameInterface(method)) {
                        continue;
                    }
                } catch {
                    continue;
                }

                var @delegate = Delegate.CreateDelegate(fieldType, source, method);
                field.SetValue(destination, @delegate);
            }
        }

        #region MethodsToDelegates ReferenceTypes

        public static void MethodsToDelegates<T1, T2>(T2 destination)
            where T2 : class
        {
            var allAccessModifiers = BindingFlags.NonPublic | BindingFlags.Public;
            Assign.MethodsToDelegates<T1, T2>(default(T1), BindingFlags.Static | allAccessModifiers, destination, BindingFlags.Instance | allAccessModifiers);
        }

        public static void MethodsToDelegates<T1, T2>(T1 source, T2 destination)
            where T2 : class
        {
            var flags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
            Assign.MethodsToDelegates<T1, T2>(source, flags, destination, flags);
        }

        public static void MethodsToDelegates<T1, T2>(T1 source, BindingFlags sourceFlags, T2 destination, BindingFlags destinationFlags)
            where T2 : class
        {
            var sourceType = typeof(T1);
            var destinationType = typeof(T2);

            var matching = sourceType.GetMethods(sourceFlags)
                .Select(method => Tuple.Create(method, destinationType.GetField(method.Name, destinationFlags)))
                .Where(tuple => tuple.Item2 != null);

            MethodsToDelegatesSetFields(matching, source, destination);
        }

        #endregion

        #region MethodsToDelegates ValueTypes

        public static void MethodsToDelegates<T1, T2>(ref T2 destination)
            where T2 : struct
        {
            var allAccessModifiers = BindingFlags.NonPublic | BindingFlags.Public;
            Assign.MethodsToDelegates<T1, T2>(default(T1), BindingFlags.Static | allAccessModifiers, ref destination, BindingFlags.Instance | allAccessModifiers);
        }

        public static void MethodsToDelegates<T1, T2>(T1 source, ref T2 destination)
            where T2 : struct
        {
            var flags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
            Assign.MethodsToDelegates<T1, T2>(source, flags, ref destination, flags);
        }

        public static void MethodsToDelegates<T1, T2>(T1 source, BindingFlags sourceFlags, ref T2 destination, BindingFlags destinationFlags)
            where T2 : struct
        {
            var sourceType = typeof(T1);
            var destinationType = typeof(T2);

            var matching = sourceType.GetMethods(sourceFlags)
                .Select(method => Tuple.Create(method, destinationType.GetField(method.Name, destinationFlags)))
                .Where(tuple => tuple.Item2 != null);

            object boxed = destination;

            MethodsToDelegatesSetFields(matching, source, boxed);

            destination = (T2)boxed;
        }

        #endregion

        static void DelegatesToFieldsSetFields(IEnumerable<Tuple<FieldInfo, FieldInfo>> pairs, object source, object destination)
        {
            foreach (var tuple in pairs) {
                var delegateField = tuple.Item1;
                var pointerField = tuple.Item2;

                var @delegate = delegateField.GetValue(source);
                if (@delegate == null) {
                    // the value is not set, we can ignore this field
                    continue;
                }
                pointerField.SetValue(destination, Marshal.GetFunctionPointerForDelegate(@delegate));
            }
        }

        #region DelegatesToPointers ReferenceTypes

        public static void DelegatesToPointers<T1, T2>(T2 destination)
            where T2 : class
        {
            var allAccessModifiers = BindingFlags.NonPublic | BindingFlags.Public;
            Assign.DelegatesToPointers<T1, T2>(default(T1), BindingFlags.Static | allAccessModifiers, destination, BindingFlags.Instance | allAccessModifiers);
        }

        public static void DelegatesToPointers<T1, T2>(T1 source, T2 destination)
            where T2 : class
        {
            var flags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
            DelegatesToPointers<T1, T2>(source, flags, destination, flags);
        }

        public static void DelegatesToPointers<T1, T2>(T1 source, BindingFlags sourceFlags, T2 destination, BindingFlags destinationFlags)
            where T2 : class
        {
            var sourceType = typeof(T1);
            var destinationType = typeof(T2);

            var matching = sourceType.GetFields()
                .Select(field => Tuple.Create(field, destinationType.GetField(field.Name, destinationFlags)))
                .Where(tuple => tuple.Item2 != null && tuple.Item2.FieldType == typeof(IntPtr));

            DelegatesToFieldsSetFields(matching, source, destination);
        }

        #endregion

        #region DelegatesToPointers ValueTypes

        public static void DelegatesToPointers<T1, T2>(ref T2 destination)
            where T2 : struct
        {
            var allAccessModifiers = BindingFlags.NonPublic | BindingFlags.Public;
            Assign.DelegatesToPointers<T1, T2>(default(T1), BindingFlags.Static | allAccessModifiers, ref destination, BindingFlags.Instance | allAccessModifiers);
        }

        public static void DelegatesToPointers<T1, T2>(T1 source, ref T2 destination)
            where T2 : struct
        {
            var flags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
            DelegatesToPointers<T1, T2>(source, flags, ref destination, flags);
        }

        public static void DelegatesToPointers<T1, T2>(T1 source, BindingFlags sourceFlags, ref T2 destination, BindingFlags destinationFlags)
            where T2 : struct
        {
            var sourceType = typeof(T1);
            var destinationType = typeof(T2);

            var matching = sourceType.GetFields()
                .Select(field => Tuple.Create(field, destinationType.GetField(field.Name, destinationFlags)))
                .Where(tuple => tuple.Item2 != null && tuple.Item2.FieldType == typeof(IntPtr));

            object boxed = destination;
            DelegatesToFieldsSetFields(matching, source, boxed);
            destination = (T2)boxed;
        }

        #endregion
    }
}

